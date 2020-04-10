#!/usr/bin/env python3
# coding: utf-8

import click
import os
import sys

from sockssl.service import SockService
from sockssl.protocol import SOCKSv4, SOCKSv5, ISOCKS
from sockssl.certstore import CertStore
from sockssl import log


log.init(log.DEBUG)


@click.group()
def cli():
    pass


@cli.command()
@click.argument('cert')
@click.argument('key')
@click.option('-org',
              '--organization', 
              type=str, 
              default='conca', 
              show_default=True,
              help='certificate organization name')
@click.option('-cn', 
              '--common-name', 
              type=str, 
              default='conca', 
              show_default=True,
              help='certificate common name')
@click.option('-f',
              '--format',
              default='PEM',
              type=click.Choice(['PEM', 'DER'], case_sensitive=False), 
              show_default=True,
              help='output format of certificate and private key')
def genca(cert, key, organization, common_name, format):
    """ Generate root CA """

    cert_store = CertStore()
    cert_store.gen_root_ca(organization, common_name)
    click.secho("[+] Generated root CA", fg="green")

    cert_store.dump_root_cert(cert, format=format)
    cert_store.dump_root_key(key, format=format)
    click.secho("[+] Saved to files", fg="green")


@cli.group()
def run():
    """ Run a standalone SOCKS server """
    
    pass


def serve_forever(host, port, cert, key, format, protocol, users):
    if cert is None or key is None:
        is_tls = False
    else:
        is_tls = True
        for fn in (cert, key):
            if not os.path.exists(fn):
                click.secho("[-] File {} not found".format(repr(fn)), fg="red")
                is_tls = False

    if is_tls:
        cert_store = CertStore()
        cert_store.load_root_cert(cert, format)
        cert_store.load_root_key(key, format)
        click.secho("[+] Loaded rootCA", fg="green")
    else:
        cert_store = None
        click.secho("[!] No valid rootCA found. We can only capture raw TLS", fg="yellow")

    service = SockService()
    service.set_host_port(host, port)
    service.set_cert_store(cert_store)
    service.set_protocol(My, users)

    service.serve_forever()


def encode(s):
    return s.encode('iso-8859-1')


@run.command()
@click.option('-u', '--user', 'users', type=str, help='authorize user', multiple=True)
def v4(users, host, port, cert, key, format):
    """ SOCKS v4 """

    if len(users) == 0:
        users = None
    else:
        users = [encode(user) for user in users]

    serve_forever(host, port, cert, key, format, SOCKSv4, users)


@run.command()
@click.option('-u', '--user', 'users', type=(str, str), help='authorize user', multiple=True)
def v5(users, host, port, cert, key, format):
    """ SOCKS v5 """

    # convert users to dict
    new_users = {}
    for user, pwd in users:
        new_users[encode(user)] = encode(pwd)
        
    if len(new_users) == 0:
        new_users = None

    serve_forever(host, port, cert, key, format, SOCKSv5, new_users)


# add more options to 'run' command
opt_cert = click.Option(['-c', '--cert'], type=str, help='rootCA certificate file')
opt_key = click.Option(['-k', '--key'], type=str, help='rootCA private key file')
opt_format = click.Option(['-f', '--format'],
                          default='PEM',
                          type=click.Choice(['PEM', 'DER'], case_sensitive=False), 
                          show_default=True,
                          help='input format of certificate and private key')
opt_host = click.Option(['-h', '--host'], type=str, default='127.0.0.1', show_default=True, help='listen host')
opt_port = click.Option(['-p', '--port'], type=int, default=9999, show_default=True, help='listen port')

run_opts = [opt_cert, opt_key, opt_format, opt_host, opt_port]
v4.params = run_opts + v4.params
v5.params = run_opts + v5.params


if __name__=="__main__":
    cli()