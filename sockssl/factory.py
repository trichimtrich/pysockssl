# coding: utf-8

from twisted.internet.protocol import Factory
from twisted.internet.threads import deferToThread
import socket
from typing import Any, List, Optional

from sockssl.certstore import CertStore, find_client_hello, is_sni
from sockssl import log


class SockFactory(Factory):
    """Twisted framework Protocol Factory:
       store global context and produce protocol handler for each connection
    """

    def __init__(
        self, protocol: Any, 
        users: Any = None, 
        cert_store: Optional[CertStore] = None, 
        data: Any = None
    ):
        """Create a SockFactory instance
        
        Args:
            protocol (Any): Class of protocol. SOCKSv4, SOCKSv5, ... or your class
            users (Any, optional): Auth users data of protocol. Defaults to None.
            cert_store (Optional[CertStore], optional): Instance of CertStore to do TLS mitm. Defaults to None.
            data (Any, optional): Global data variable share between connection. Defaults to None.
        """        

        self.protocol = protocol
        self.users = users
        self.cert_store = cert_store
        self.data = data


    def do_sslpeek(self, client_socks, server_socks):
        # Connection calls this method for TLS mitm while establishing new SOCKS tunnel

        # not doing TLS mitm, capture only raw TLS
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
            errback=self.sslpeek_err, errbackArgs=(client_socks.peer_str, ),
        )
        deferred.addErrback(self.sslpeek_cb_err, client_socks.peer_str)


    def sslpeek_err(self, err, peer_str):
        # must be find_client_hello error, means not ssl
        pass


    def sslpeek_cb_err(self, err, peer_str):
        log.error("%s - %s", peer_str, err)


    def sslpeek_cb(self, sni, client_socks, server_socks):
        # Callback of sslpeek. Start TLS context for both side

        if sni:
            log.debug("%s - SSL SNI: %s", client_socks.peer_str, sni)
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
        # Read first packet and parse ClientHello if it is TLS handshake

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
