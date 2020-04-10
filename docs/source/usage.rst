Usage
=================

You can use this package as standalone cli tool, or import it in your project to do other tasks like capture packet or filter them with your rules.

With CLI
----------

.. code-block:: bash

    $ sockssl --help
    Usage: sockssl [OPTIONS] COMMAND [ARGS]...

    Options:
    --help  Show this message and exit.

    Commands:
    genca  Generate root CA
    run    Run a standalone SOCKS server

- Generate rootCA with ON and CN

.. code-block:: bash

    sockssl genca rootCA.crt rootCA.key -org mycompany -cn myCA

- Run SOCKSv4 / SOCKSv5 server (no TLS mitm)

.. code-block:: bash

    sockssl run v4
    sockssl run v5

- Run SOCKSv4 / SOCKSv5 server with TLS mitm

.. code-block:: bash

    sockssl run v4 -c rootCA.crt -k rootCA.key -h 0.0.0.0 -p 9999
    sockssl run v5 -c rootCA.crt -k rootCA.key -h 0.0.0.0 -p 9999

- Run SOCKSv4 / SOCKSv5 server with TLS mitm + authentication

.. code-block:: bash

    sockssl run v4 -c rootCA.crt -k rootCA.key -h 0.0.0.0 -p 9999 -u user1 -u user2
    sockssl run v5 -c rootCA.crt -k rootCA.key -h 0.0.0.0 -p 9999 -u user1 pass1 -u user2 pass2

- Don't forget to trust `rootCA.crt` in you client if you want to see data in TLS stream

With API
----------

- Run a standalone SOCKSv4 server

.. code-block:: python

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

- Capture TLS stream with SOCKSv5

.. code-block:: python

    from sockssl.certstore import CertStore
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

    cs = CertStore()
    # generate root ca
    cs.gen_root_ca(org='myON', cn='myCN')
    # save to file, dont forget to trust myroot.crt in client
    cs.dump_root_cert('myroot.crt')
    cs.dump_root_key('myroot.key')

    svc = SockService()
    svc.set_host_port(HOST, PORT)
    svc.set_cert_store(cs)
    svc.set_protocol(MySOCKS)

    svc.serve_forever()

- You can change the data stream before send to server or back to client

- Other examples can check on ``/examples`` directory