# coding: utf-8

import struct
import socket

from twisted.python import compat
from twisted.internet import reactor, protocol, defer

from sockssl import log
from sockssl.protocol.isocks import ISOCKS


class EnumState(object):
    TCP_INIT = 1
    AUTH_RFC1929 = 2
    REQUEST = 3
    REQUEST2 = 4
    DONE = 5
    DIE = -1



class EnumSOCKS(object):
    VERSION = 5
    
    CMD_CONNECT = 1
    CMD_BIND = 2
    CMD_UDP_ASSOCIATE = 3

    Cmds = (CMD_CONNECT, CMD_BIND, CMD_UDP_ASSOCIATE)

    ATYP_IPV4 = 1
    ATYP_IPV6 = 4
    ATYP_DOMAIN = 3

    AUTH_SUCCESS = 0
    AUTH_FAILED = 1



class EnumMethod(object):
    NO_AUTHENTICATION = 0
    GSSAPI = 1
    USERNAME_PASSWORD = 2
    NOT_ACCEPTABLE = 0xff
    
    Supported = (NO_AUTHENTICATION, USERNAME_PASSWORD)



class EnumReply(object):
    SUCCEEDED = 0
    GENERAL_SOCKS_SERVER_FAILURE = 1
    CONNECTION_NOT_ALLOWED = 2
    NETWORK_UNREACHABLE = 3
    HOST_UNREACHABLE = 4
    CONNECTION_REFUSED = 5
    TTL_EXPIRED = 6
    COMMAND_NOT_SUPPORTED = 7
    ADDRESS_TYPE_ERROR = 8



class MyByteArray(bytearray):
    def add(self, data):
        self.extend(data)


    def getb(self):
        return self.pop(0)


    def getN(self, n):
        b = self[:n]
        del self[:n]
        return b


    def unpackN(self, fmt, n):
        b = self.getN(n)
        return struct.unpack(fmt, b)



class SOCKSv5Outgoing(protocol.Protocol):
    def __init__(self, socks):
        self.socks = socks


    def connectionMade(self):
        peer = self.transport.getPeer()
        self.socks.addr_server = peer
        self.socks.reply(EnumReply.SUCCEEDED, server=peer.host, port=peer.port)
        self.socks.otherConn = self
        self.socks.factory.do_sslpeek(self.socks, self)


    def connectionLost(self, reason):
        self.socks.transport.loseConnection()


    def dataReceived(self, data):
        self.socks.write(data)


    def write(self,data):
        self.transport.write(data)



class SOCKSv5(protocol.Protocol, ISOCKS):
    """Implementation of SOCKSv5 protocol compatiables with ISOCKS interface"""

    def __init__(self, reactor=reactor):
        self._reactor = reactor
        self._state = EnumState.TCP_INIT
        self.peer_str = ''


    def connectionMade(self):
        peer = self.transport.getPeer()
        self.addr_client = peer
        self.peer_str = "{} {}:{}".format(peer.type, peer.host, peer.port)
        log.debug("%s - Client connected", self.peer_str)
        self._buf = MyByteArray()
        self.otherConn = None

        # callback
        self.on_connect()


    def dataReceived(self, data):
        if self.otherConn:
            # callback
            data = self.on_recv_client(data)
            self.otherConn.write(data)
            return

        self._buf.add(data)
        if self._state == EnumState.TCP_INIT:
            self._tcp_init()
        elif self._state == EnumState.AUTH_RFC1929:
            self._auth_rfc1929()
        elif self._state == EnumState.REQUEST:
            self._request()


    def _die(self, msg=None):
        self._state = EnumState.DIE
        if msg != None: 
            log.error("%s - %s", self.peer_str, msg, layer=1)
        
        # callback
        self.on_socks_failed()
        
        self.transport.loseConnection()


    def _tcp_init(self):
        buf = self._buf
        
        if len(buf) < 2: return

        ver, n_methods = buf.unpackN("!BB", 2)

        if ver != EnumSOCKS.VERSION:
            self._die("Version mismatch")
            return

        if n_methods == 0:
            self._die("Number of method is invalid")
            return

        if len(buf) < n_methods: return

        methods = buf.getN(n_methods)

        if self.factory.users is None:
            method = EnumMethod.NO_AUTHENTICATION 
        else:
            method = EnumMethod.USERNAME_PASSWORD

        n = len(set(methods).intersection(EnumMethod.Supported))
        if n == 0:
            method = EnumMethod.NOT_ACCEPTABLE

        self.transport.write(struct.pack("!BB", EnumSOCKS.VERSION, method))
        if method == EnumMethod.NO_AUTHENTICATION:
            self._state = EnumState.REQUEST
        elif method == EnumMethod.USERNAME_PASSWORD:
            self._state = EnumState.AUTH_RFC1929
        else:
            self._die("Method is not supported")
            return

        self._buf = buf
        

    def _reply_rfc1929(self, code, msg=None):
        self.transport.write(struct.pack("!BB", EnumSOCKS.VERSION, code))
        if code != EnumSOCKS.AUTH_SUCCESS:
            self._die(msg)


    def _auth_rfc1929(self):
        buf = self._buf

        if len(buf) < 2: return

        ver, u_len = buf.unpackN("!BB", 2)

        if ver != 1:
            self._die("Version mismatch")
            return

        if u_len == 0:
            self._reply_rfc1929(EnumSOCKS.AUTH_FAILED, "Invalid username length")
            return
        
        if u_len >= len(buf): return

        u_name = bytes(buf.getN(u_len))
        p_len = buf.getb()

        if p_len > len(buf): return

        if p_len == 0:
            self._reply_rfc1929(EnumSOCKS.AUTH_FAILED, "Invalid password length")
            return

        pwd = bytes(buf.getN(p_len))

        # check now
        if self.factory.users[u_name] == pwd:
            log.debug("%s - Authenticated", self.peer_str)
            self._reply_rfc1929(EnumSOCKS.AUTH_SUCCESS)
            self._state = EnumState.REQUEST
        else:
            self._reply_rfc1929(EnumSOCKS.AUTH_FAILED, "Wrong username or password")

        self._buf = buf


    def reply(self, reply, addr_type=EnumSOCKS.ATYP_IPV4, server="127.0.0.1", port=8888, msg=None):
        svr_int = struct.unpack("!I", socket.inet_aton(server))[0]
        self.transport.write(struct.pack("!4BIH", EnumSOCKS.VERSION, reply, 0, addr_type, svr_int, port))
        if reply == EnumReply.SUCCEEDED:
            log.debug("%s - SOCKS established", self.peer_str)
            self._state = EnumState.DONE

            # callback
            self.on_socks_established()
        else:
            self._die(msg)


    def _request(self):
        buf = self._buf

        if len(buf) < 4: return

        ver, cmd, _, addr_type = buf.unpackN("!4B", 4)
        
        if ver != EnumSOCKS.VERSION:
            self.reply(EnumReply.GENERAL_SOCKS_SERVER_FAILURE, msg="Version mismatch")
            return

        if cmd not in EnumSOCKS.Cmds:
            self.reply(EnumReply.COMMAND_NOT_SUPPORTED, msg="Command not support")
            return

        if addr_type == EnumSOCKS.ATYP_IPV4:
            server = socket.inet_ntoa(buf.getN(4))
            deferred = defer.succeed(server)
        elif addr_type == EnumSOCKS.ATYP_IPV6:
            server = compat.inet_ntop(socket.AF_INET6, buf.getN(16))
            deferred = defer.succeed(server)
        elif addr_type == EnumSOCKS.ATYP_DOMAIN:
            host_len = buf.getb()
            host = buf.getN(host_len)
            deferred = self._reactor.resolve(host)
        else:
            self.reply(EnumReply.ADDRESS_TYPE_ERROR, msg="Address Type not support")
            return

        port = buf.unpackN("!H", 2)[0]
        deferred.addCallback(self._request2, port, cmd)

        self._state = EnumState.REQUEST2
        self.buf = buf


    def _request2(self, server, port, cmd):
        if cmd == EnumSOCKS.CMD_CONNECT:
            d = self.connectClass(server, port, SOCKSv5Outgoing, self)
            d.addErrback(lambda result, self = self: self.reply(EnumReply.CONNECTION_REFUSED))
        elif cmd == EnumSOCKS.CMD_UDP_ASSOCIATE:
            pass
        else:
            # we dont have to use BIND
            self.reply(EnumReply.COMMAND_NOT_SUPPORTED)


    def connectionLost(self, reason):
        if self.otherConn:
            self.otherConn.transport.loseConnection()

        log.debug("%s - Client disconnected", self.peer_str)

        # callback
        self.on_disconnect()


    def connectClass(self, host, port, klass, *args):
        return protocol.ClientCreator(self._reactor, klass, *args).connectTCP(host,port)


    def write(self, data):
        # callback
        data = self.on_recv_server(data)
        self.transport.write(data)
