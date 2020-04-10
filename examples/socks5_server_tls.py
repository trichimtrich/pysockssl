#!/usr/bin/env python3
# coding: utf-8

from sockssl.certstore import CertStore
from sockssl.service import SockService
from sockssl.protocol import SOCKSv5
from sockssl import log

# not necessary, but for debug only
log.init(log.DEBUG)

HOST = '0.0.0.0'
PORT = 9999

cs = CertStore()
# generate root ca
cs.gen_root_ca(org='myON', cn='myCN')
# save to file, dont forget to trust myroot.crt in client
cs.dump_root_cert('myroot.crt')
cs.dump_root_key('myroot.key')


svc = SockService()
svc.set_host_port(HOST, PORT)
svc.set_protocol(SOCKSv5)
svc.set_cert_store(cs)

svc.serve_forever()