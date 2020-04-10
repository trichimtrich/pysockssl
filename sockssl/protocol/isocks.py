# coding: utf-8

from twisted.internet.interfaces import IAddress, IProtocolFactory


class ISOCKS(object):
    """Interface to interact with SOCKS protocol"""

    #: Client information
    addr_client: IAddress = None
    
    #: Server information
    addr_server: IAddress = None
    
    #: Factory instance of current protocol connection
    factory: IProtocolFactory = None


    def on_connect(self):
        """Trigger when a client connected"""

        pass


    def on_disconnect(self):
        """Trigger when client disconnected"""

        pass


    def on_socks_failed(self):
        """Trigger when a SOCKS connection failed to establish"""

        pass


    def on_socks_established(self):
        """Trigger when a SOCKS tunnel established"""

        pass


    def on_recv_client(self, data: bytes) -> bytes:
        """Process data sent from client to server
        
        Args:
            data (bytes): Data from client
        
        Returns:
            bytes: Data will be sent to server
        """

        return data


    def on_recv_server(self, data: bytes) -> bytes:
        """Process data sent back from server to client
        
        Args:
            data (bytes): Data got from server
        
        Returns:
            bytes: Data will be sent back to client
        """        

        return data

