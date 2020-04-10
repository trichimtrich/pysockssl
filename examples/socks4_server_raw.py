#!/usr/bin/env python3
# coding: utf-8

from sockssl.service import SockService
from sockssl.protocol import SOCKSv4
from sockssl import log

# not necessary, but for debug only
log.init(log.DEBUG)

HOST = '0.0.0.0'
PORT = 9999

svc = SockService()
svc.set_host_port(HOST, PORT)
svc.set_protocol(SOCKSv4)

svc.serve_forever()