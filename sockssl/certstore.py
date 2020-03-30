# coding: utf-8

from OpenSSL import crypto
import time
import ipaddress
from twisted.internet._sslverify import OpenSSLCertificateOptions

from kaitaistruct import KaitaiStream
import io

from sockssl.tls_client_hello import TlsClientHello

# Copied 99.99%, yup, Im shameless 😏
# Ref: https://github.com/mitmproxy/mitmproxy/blob/master/mitmproxy/certs.py

class CertStore(object):
    def __init__(self, root_cert=None, root_key=None):
        self.root_cert = root_cert # type: crypto.X509
        self.root_key = root_key # type: crypto.PKey

        self._root_ctx = None
        self._store = {}


    @staticmethod
    def _ssl_format(format):
        format = format.upper()
        if format == "PEM":
            return crypto.FILETYPE_PEM
        elif format == "DER":
            return crypto.FILETYPE_ASN1
        else:
            return crypto.FILETYPE_TEXT


    def _load(self, func, filename, format):
        with open(filename, "rb") as f:
            return func(self._ssl_format(format), f.read())

    def load_root_key(self, filename, format="PEM"):
        self.root_key = self._load(crypto.load_privatekey, filename, format)

    def load_root_cert(self, filename, format="PEM"):
        self.root_cert = self._load(crypto.load_certificate, filename, format)


    def _dump(self, func, data, filename, format):
        if data is None:
            raise Exception("Cannot dump None value to " + format)
        buffer = func(self._ssl_format(format), data)
        with open(filename, "wb") as f:
            f.write(buffer)

    def dump_root_key(self, filename, format="PEM"):
        self._dump(crypto.dump_privatekey, self.root_key, filename, format)

    def dump_root_cert(self, filename, format="PEM"):
        self._dump(crypto.dump_certificate, self.root_cert, filename, format)


    def root_ctx(self):
        # TODO: toctou?
        if self._root_ctx is None:
            self._root_ctx = OpenSSLCertificateOptions(privateKey=self.root_key,
                                                       certificate=self.root_cert)
                                                       
        return self._root_ctx
            
    
    def gen_root_ca(self, org, cn, exp=94608000, key_size=2048):
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

    
    def _gen_dummy_cert(self, commonname, sans, organization):
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
    def dummy_ctx(self, sni):
        commonname = sni[0].lower()
        if commonname not in self._store:
            self._gen_dummy_cert(commonname, sni, "to chuc ao den")
        return self._store[commonname]
        

# Ref: https://github.com/mitmproxy/mitmproxy/tree/master/mitmproxy/contrib/kaitaistruct

def find_client_hello(packet):
    # work fine with TLS 1.2
    # TODO: other TLS version
    return TlsClientHello(KaitaiStream(io.BytesIO(packet))).client_hello


def is_sni(obj):
    return isinstance(obj, TlsClientHello.Sni)