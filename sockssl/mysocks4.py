# coding: utf-8

from twisted.protocols.socks import SOCKSv4, SOCKSv4Outgoing
from sockssl import mylog as log


class MySOCKSv4Outgoing(SOCKSv4Outgoing):
    def connectionMade(self):
        super().connectionMade()
        self.socks.factory.do_sslpeek(self.socks, self)


class MySOCKSv4(SOCKSv4):
    def connectClass(self, host, port, klass, *args):
        return super().connectClass(host, port, MySOCKSv4Outgoing, *args)


    def connectionMade(self):
        super().connectionMade()
        peer = self.transport.getPeer()
        self.peer = "{} {}:{}".format(peer.type, peer.host, peer.port)
        log.debug("%s - Client connected", self.peer)


    def makeReply(self, reply, version=0, port=0, ip="0.0.0.0"):
        super().makeReply(reply, version, port, ip)
        if reply == 90:
            log.info("%s - SOCKS established", self.peer)


    def connectionLost(self, reason):
        super().connectionLost(reason)
        log.info("%s - Client disconnected", self.peer)


    def authorize(self, code, server, port, user):
        if self.factory.users is not None and user not in self.factory.users:
            log.error("Wrong username")
            return False

        return True