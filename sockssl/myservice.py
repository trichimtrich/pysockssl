# coding: utf-8

from twisted.internet import reactor
import click

from sockssl.myfactory import MyFactory
from sockssl.mysocks4 import MySOCKSv4
from sockssl.mysocks5 import MySOCKSv5


class MyService(object):
    def __init__(self):
        self.host = self.port = None
        self.cert_store = None
        self.protocol = self.users = None


    def set_host_port(self, host, port):
        self.host = host
        self.port = port


    def set_cert_store(self, cert_store):
        self.cert_store = cert_store

    
    def set_protocol(self, protocol, users):
        self.protocol = protocol
        self.users = users
    

    def serve_forever(self):
        for var in ('host', 'port', 'protocol'):
            if getattr(self, var) is None:
                click.secho("[-] {} cannot be None".format(repr(var)), fg="red")
                return

        protocol = None
        if self.protocol == 'v4':
            protocol = MySOCKSv4
        elif self.protocol == 'v5':
            protocol = MySOCKSv5
        else:
            click.secho("[-] Unknown protocol {}".format(repr(self.protocol)), fg="red")
            return

        factory = MyFactory(protocol, self.users, self.cert_store)
        reactor.listenTCP(self.port, factory, interface=self.host)
        click.secho("[+] SOCKS{} is listening on {}:{}".format(self.protocol, self.host, self.port))
        reactor.run()