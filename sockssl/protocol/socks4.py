# coding: utf-8

from twisted.protocols.socks import SOCKSv4 as TSOCKSv4
from twisted.protocols.socks import SOCKSv4Outgoing as TSOCKSv4Outgoing

from sockssl.protocol.isocks import ISOCKS
from sockssl import log


class SOCKSv4Outgoing(TSOCKSv4Outgoing):
    def connectionMade(self):
        super().connectionMade()
        self.socks.factory.do_sslpeek(self.socks, self)
        self.socks.addr_server = self.transport.getPeer()


class SOCKSv4(TSOCKSv4, ISOCKS):
    """Implementation of SOCKSv4 protocol compatiables with ISOCKS interface"""

    def connectClass(self, host, port, klass, *args):
        return super().connectClass(host, port, SOCKSv4Outgoing, *args)


    def connectionMade(self):
        super().connectionMade()
        
        peer = self.transport.getPeer()
        self.addr_client = peer
        self.peer_str = "{} {}:{}".format(peer.type, peer.host, peer.port)
        log.debug("%s - Client connected", self.peer_str)

        # callback
        self.on_connect()


    def makeReply(self, reply, version=0, port=0, ip="0.0.0.0"):
        if reply == 90:
            log.debug("%s - SOCKS established", self.peer_str)

            # callback
            self.on_socks_established()
        else:
            # callback
            self.on_socks_failed()

        super().makeReply(reply, version, port, ip)


    def connectionLost(self, reason):
        super().connectionLost(reason)

        log.debug("%s - Client disconnected", self.peer_str)

        # callback
        self.on_disconnect()


    def authorize(self, code, server, port, user):
        if self.factory.users is not None and user not in self.factory.users:
            log.error("Wrong username")
            return False

        return True

    
    def dataReceived(self, data):
        if self.otherConn:
            # callback
            data = self.on_recv_client(data)
        
        super().dataReceived(data)
    

    def write(self, data):
        data = self.on_recv_server(data)
        super().write(data)