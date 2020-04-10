#!/usr/bin/env python3
# coding: utf-8

from sockssl.service import SockService
from sockssl.protocol import SOCKSv5, ISOCKS
from sockssl import log

# not necessary, but for debug only
log.init(log.ERROR)

HOST = '0.0.0.0'
PORT = 9999


class MySOCKS(SOCKSv5, ISOCKS):
    def _addr(self, addr):
        return '{}:{}:{}'.format(addr.type, addr.host, addr.port)

    def on_connect(self):
        print('Client {} has entered'.format(self._addr(self.addr_client)))
    

    def on_disconnect(self):
        print('Client {} disconnected'.format(self._addr(self.addr_client)))


    def on_socks_established(self):
        print('Client {} created tunnel with {}'.format(self._addr(self.addr_client),
                                                        self._addr(self.addr_client)))


    def on_recv_client(self, data):
        print('Client {:24} ---> Server {:24}: {:4} bytes: {}'.format(
            self._addr(self.addr_client),
            self._addr(self.addr_server),
            len(data),
            data[:16]
        ))

        return data


    def on_recv_server(self, data):
        print('Client {:24} <--- Server {:24}: {:4} bytes: {}'.format(
            self._addr(self.addr_client),
            self._addr(self.addr_server),
            len(data),
            data[:16]
        ))

        return data


svc = SockService()
svc.set_host_port(HOST, PORT)
svc.set_protocol(MySOCKS)

svc.serve_forever()