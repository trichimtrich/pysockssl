# coding: utf-8

from OpenSSL import crypto
import time
import ipaddress
from twisted.internet._sslverify import OpenSSLCertificateOptions

from kaitaistruct import KaitaiStream
import io

from typing import Optional, Callable, Union, Any, List

from sockssl.tls_client_hello import TlsClientHello

# Copied 99.99%, yup, Im shameless 😏
# Ref: https://github.com/mitmproxy/mitmproxy/blob/master/mitmproxy/certs.py


class CertStore(object):
    """Manage Root Certificate Authority, and generate Dummy Certificate"""
    
    def __init__(
        self, 
        root_cert: Optional[crypto.X509] = None, 
        root_key: Optional[crypto.PKey] = None
    ):
        """Create a CertStore instance
        
        Args:
            root_cert (OpenSSL.crypto.X509, optional): rootCA certificate - x509 instance. Defaults to None.
            root_key (OpenSSL.crypto.PKey, optional): rootCA private key - PKey instance. Defaults to None.
        """

        #: OpenSSL.crypto.x509 (certificate) instance of rootCA
        self.root_cert = root_cert 
        #: OpenSSL.crypto.PKey (private key) instance of rootCA
        self.root_key = root_key 

        self._root_ctx = None
        self._store = {}


    @staticmethod
    def _ssl_format(format: str) -> Any:
        """Convert format from string to OpenSSL enum"""

        format = format.upper()
        if format == "PEM":
            return crypto.FILETYPE_PEM
        elif format == "DER":
            return crypto.FILETYPE_ASN1
        else:
            return crypto.FILETYPE_TEXT


    def _load(self, func: Callable, filename: str, format: str) -> Union[crypto.X509, crypto.PKey]:
        """Trigger callable to load file with format"""

        with open(filename, "rb") as f:
            return func(self._ssl_format(format), f.read())


    def load_root_key(self, filename: str, format: str = "PEM"):
        """Load rootCA private key from file
        
        Args:
            filename (str): path to private key file
            format (str, optional): format of private key, support PEM/DER. Defaults to "PEM".
        """

        self.root_key = self._load(crypto.load_privatekey, filename, format)


    def load_root_cert(self, filename: str, format: str="PEM"):
        """Load rootCA certificate from file
        
        Args:
            filename (str): path to certificate file
            format (str, optional): format of certificate, support PEM/DER. Defaults to "PEM".
        """

        self.root_cert = self._load(crypto.load_certificate, filename, format)


    def _dump(
        self, 
        func: Callable, 
        data: Union[crypto.X509, crypto.PKey], 
        filename: str, 
        format: str
    ):
        """Trigger callable to save file with format"""

        if data is None:
            raise Exception("Cannot dump None value to " + format)
        buffer = func(self._ssl_format(format), data)
        with open(filename, "wb") as f:
            f.write(buffer)


    def dump_root_key(self, filename: str, format: str = "PEM"):
        """Dump rootCA private key to file
        
        Args:
            filename (str): path to private key file
            format (str, optional): format of private key, support PEM/DER. Defaults to "PEM".
        """

        self._dump(crypto.dump_privatekey, self.root_key, filename, format)


    def dump_root_cert(self, filename: str, format: str = "PEM"):
        """Dump rootCA certificate to file
        
        Args:
            filename (str): path to certificate file
            format (str, optional): format of certificate, support PEM/DER. Defaults to "PEM".
        """

        self._dump(crypto.dump_certificate, self.root_cert, filename, format)


    def root_ctx(self) -> OpenSSLCertificateOptions:
        """Get SSL context of rootCA ceritficate. Use for passing to twisted StartTLS
        
        Returns:
            twisted.internet._sslverify.OpenSSLCertificateOptions
        """

        # TODO: toctou?
        if self._root_ctx is None:
            self._root_ctx = OpenSSLCertificateOptions(privateKey=self.root_key,
                                                       certificate=self.root_cert)
                                                       
        return self._root_ctx

    
    def gen_root_ca(self, org: str, cn: str, exp: int = 94608000, key_size: int = 2048):
        """Generate rootCA certificate + privatekey and store in root_key, root_cert
        
        Args:
            org (str): Organization name
            cn (str): Common Name
            exp (int, optional): Expiration time in second. Defaults to 94608000 == 3 years
            key_size (int, optional): RSA key size (1024/2048/...). Defaults to 2048.
        """        
                                
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, key_size)
        cert = crypto.X509()
        cert.set_serial_number(int(time.time() * 10000))
        cert.set_version(2)
        cert.get_subject().CN = cn
        cert.get_subject().O = org
        cert.gmtime_adj_notBefore(-3600 * 48)
        cert.gmtime_adj_notAfter(exp)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(key)
        cert.add_extensions([
            crypto.X509Extension(
                b"basicConstraints",
                True,
                b"CA:TRUE"
            ),
            crypto.X509Extension(
                b"nsCertType",
                False,
                b"sslCA"
            ),
            crypto.X509Extension(
                b"extendedKeyUsage",
                False,
                b"serverAuth,clientAuth,emailProtection,timeStamping,msCodeInd,msCodeCom,msCTLSign,msSGC,msEFS,nsSGC"
            ),
            crypto.X509Extension(
                b"keyUsage",
                True,
                b"keyCertSign, cRLSign"
            ),
            crypto.X509Extension(
                b"subjectKeyIdentifier",
                False,
                b"hash",
                subject=cert
            ),
        ])
        cert.sign(key, "sha256")
        self.root_key = key
        self.root_cert = cert

    
    def _gen_dummy_cert(self, commonname: str, sans: List[str], organization: str):
        """Generate dummy certificate and store in instance context"""

        # reuse privkey of root_ca, no need to regenerate
        privkey = self.root_key
        cacert = self.root_cert

        ss = []
        for i in sans:
            try:
                ipaddress.ip_address(i.decode("ascii"))
            except ValueError:
                ss.append(b"DNS:%s" % i)
            else:
                ss.append(b"IP:%s" % i)
        ss = b", ".join(ss)

        cert = crypto.X509()
        cert.gmtime_adj_notBefore(-3600 * 48)
        cert.gmtime_adj_notAfter(63072000)
        cert.set_issuer(cacert.get_subject())
        if commonname is not None and len(commonname) < 64:
            cert.get_subject().CN = commonname
        if organization is not None:
            cert.get_subject().O = organization
        cert.set_serial_number(int(time.time() * 10000))
        if ss:
            cert.set_version(2)
            cert.add_extensions(
                [crypto.X509Extension(b"subjectAltName", False, ss)])
        cert.add_extensions([
            crypto.X509Extension(
                b"extendedKeyUsage",
                False,
                b"serverAuth,clientAuth"
            )
        ])
        cert.set_pubkey(cacert.get_pubkey())
        cert.sign(privkey, "sha256")
        ctx = OpenSSLCertificateOptions(privateKey=privkey, certificate=cert)

        # TODO: toctou, but ... no but
        commonname = commonname.lower()
        if commonname in self._store:
            return
        self._store[commonname] = ctx


    # expect sni is a good array, dont be lame.
    def dummy_ctx(self, sni: List[str]) -> OpenSSLCertificateOptions:
        """Get SSL context of dummy ceritficate from SNI list.
        Use for passing to twisted StartTLS
        
        Args:
            sni (List[str]): List of domain name, ips
        
        Returns:
            twisted.internet._sslverify.OpenSSLCertificateOptions
        """        

        commonname = sni[0].lower()
        if commonname not in self._store:
            self._gen_dummy_cert(commonname, sni, "to chuc ao den")
        return self._store[commonname]
        

# Ref: https://github.com/mitmproxy/mitmproxy/tree/master/mitmproxy/contrib/kaitaistruct

def find_client_hello(packet: bytes) -> TlsClientHello:
    """Parse ClientHello Packet of TLS 1.2
    
    Args:
        packet (bytes): stream of packet
    
    Returns:
        TlsClientHello
    """    
    # work fine with TLS 1.2
    # TODO: other TLS version
    return TlsClientHello(KaitaiStream(io.BytesIO(packet))).client_hello


def is_sni(obj: object) -> bool:
    """Check if an object is SNI instance
    
    Args:
        obj (object)
    
    Returns:
        bool
    """    
    return isinstance(obj, TlsClientHello.Sni)