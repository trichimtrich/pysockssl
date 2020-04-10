# coding: utf-8

from twisted.internet import reactor
from typing import Optional, List, Tuple, Any
import click

from sockssl.factory import SockFactory
from sockssl.certstore import CertStore

class SockService(object):
    """Service class to manage certstore and serve your socks protocol"""

    def __init__(
        self, 
        host: Optional[str] = None, 
        port: Optional[int] = None,
        cert_store: Optional[CertStore] = None,
        protocol: Any = None,
        users: Any = None,
        data: Any = None
    ):
        """Create a SockService instance
        
        Args:
            host (Optional[str], optional): Interface as ip or hostname. Defaults to None.
            port (Optional[int], optional): Port in integer. Defaults to None.
            cert_store (Optional[CertStore], optional): Instance of CertStore Class. Defaults to None.
            protocol (Any, optional): Class of protocol you want to serve. Defaults to None.
            users (Any, optional): Auth users data of protocol. List[str] for SOCKSv4, List[Tuple[str, str]] for SOCKSv5. Defaults to None.
            data (Any, optional): Global data for that protocol (like auth data), will pass to SockFactory. Defaults to None.
        """        

        self.host = host
        self.port = port
        self.cert_store = cert_store
        self.protocol = protocol
        self.users = users
        self.data = data


    def set_host_port(self, host: str, port: int):
        """Set listen interface and port for service
        
        Args:
            host (str): Interface as ip or hostname
            port (int): Port in integer
        """        

        self.host = host
        self.port = port


    def set_cert_store(self, cert_store: Optional[CertStore] = None):
        """Set CertStore instance to intercept TLS traffic.
           Set to None if you don't want to do TLS mitm. 
        
        Args:
            cert_store (Optional[CertStore], optional): Instance of CertStore Class. Defaults to None.
        """

        self.cert_store = cert_store

    
    def set_protocol(self, protocol: Any, users: Any = None):
        """Set protocol and users data for service to serve, usually SOCKv4 or SOCKSv5.
        
        Args:
            protocol (Any): Class of protocol you want to serve
            users (Any, optional): Auth users data of protocol. List[str] for SOCKSv4, List[Tuple[str, str]] for SOCKSv5. Defaults to None.
        """      

        self.protocol = protocol
        self.users = users

    
    def set_data(self, data: Any = None):
        """Set global data share between connection
        
        Args:
            data (Any, optional): Global data for that protocol (like auth data), will pass to SockFactory. Defaults to None.
        """        

        self.data = data
    

    def serve_forever(self):
        """Listen TCP and run reactor forever"""

        for var in ('host', 'port', 'protocol'):
            if getattr(self, var) is None:
                click.secho("[-] {} cannot be None".format(repr(var)), fg="red")
                return

        factory = SockFactory(self. protocol, self.users, self.cert_store, self.data)
        reactor.listenTCP(self.port, factory, interface=self.host)
        click.secho("[+] SOCKS{} is listening on {}:{}".format(self.protocol, self.host, self.port))
        reactor.run()