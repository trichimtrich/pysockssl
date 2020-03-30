# coding: utf-8

from twisted.internet.protocol import Factory
from twisted.internet.threads import deferToThread
import socket

from sockssl.certstore import find_client_hello, is_sni
from sockssl import mylog as log
from sockssl.mysocks4 import MySOCKSv4
from sockssl.mysocks5 import MySOCKSv5


class MyFactory(Factory):
    def __init__(self, protocol, users, cert_store):
        self.protocol = protocol
        self.users = users
        self.cert_store = cert_store


    def do_sslpeek(self, client_socks, server_socks):
        # not valid rootCA loaded, capture only raw TLS
        if self.cert_store is None:
            return

        # pause producer to consume first packet as TLS
        # this is blocking for startTLS method, so no magic ?
        client_socks.transport.pauseProducing()
        server_socks.transport.pauseProducing()
        client_socks.transport.socket.setblocking(1)
        server_socks.transport.socket.setblocking(1)

        deferred = deferToThread(self.sslpeek, client_socks, server_socks)
        deferred.addCallbacks(
            callback=self.sslpeek_cb, callbackArgs=(client_socks, server_socks),
            errback=self.sslpeek_err, errbackArgs=(client_socks.peer, ),
        )
        deferred.addErrback(self.sslpeek_cb_err, client_socks.peer)


    def sslpeek_err(self, err, peer):
        # must be find_client_hello error, means not ssl
        pass


    def sslpeek_cb_err(self, err, peer):
        log.error("%s - %s", err)


    def sslpeek_cb(self, sni, client_socks, server_socks):
        if sni:
            log.debug("%s - SSL SNI: %s", client_socks.peer, sni)
            server_socks.transport.startTLS(self.cert_store.root_ctx())
            client_socks.transport.startTLS(self.cert_store.dummy_ctx(sni))
        else:
            raise Exception("Unknown error, expect sni")

        # release them back to reactor and procuder
        client_socks.transport.socket.setblocking(0)
        server_socks.transport.socket.setblocking(0)
        client_socks.transport.resumeProducing()
        server_socks.transport.resumeProducing()


    def sslpeek(self, client_socks, server_socks):
        packet = client_socks.transport.socket.recv(65535, socket.MSG_PEEK)
        client_hello = find_client_hello(packet)

        extensions = client_hello.extensions.extensions
        sni = []
        for ex in extensions:
            if is_sni(ex.body):
                for server_name in ex.body.server_names:
                    sni.append(server_name.host_name)
                    break

        if not sni:
            peer = server_socks.transport.getPeer()
            sni.append(peer.host)

        return sni
