import pytest
from autossl.certificates import DeployableCertificate
from cryptography.x509 import Certificate
import re
from autossl.keygen import RSAPrivateKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey as cryptorsakey


def pvtkey_to(key: cryptorsakey, to: str | bytes):
    d: bytes = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()
    )[:-1]
    if isinstance(to, bytes): return d
    return d.decode(encoding='utf-8')


class TestDeployableCertificate:

    @pytest.mark.parametrize("key_as_native", [False, True])
    def test_init(self, certificate_chain, pvtkey, key_as_native):
        chain, key = certificate_chain('foo.com', pvtkey)  # generate a certificate chain and key pair
        # key loads as string or native object
        key = RSAPrivateKey(pvtkey_to(key, str)) if key_as_native else pvtkey_to(key, str)
        cert = DeployableCertificate(chain.decode(), key)
        assert isinstance(cert._root_cert, Certificate)
        assert isinstance(cert._ica_cert, Certificate)
        assert isinstance(cert._domain_cert, Certificate)

    def test_domain_cert(self, certificate_chain, pvtkey):
        chain, key = certificate_chain('foo.com', pvtkey)
        cert = DeployableCertificate(chain.decode(), pvtkey_to(key, str))
        assert b'BEGIN CERTIFICATE' in cert.domain_pem
        assert b'END CERTIFICATE' in cert.domain_pem
        assert cert.domain_pem[-1] != b'\n'
        assert b'foo.com' in cert.domain_der

    def test_ica_cert_properties(self, certificate_chain, pvtkey):
        chain, key = certificate_chain('foo.com', pvtkey)
        cert = DeployableCertificate(chain.decode(), pvtkey_to(key, str))
        assert b'BEGIN CERTIFICATE' in cert.ica_pem
        assert b'END CERTIFICATE' in cert.ica_pem
        assert cert.ica_pem[-1] != b'\n'
        assert b'Intermediate CA' in cert.ica_der

    def test_root_cert_properties(self, certificate_chain, pvtkey):
        chain, key = certificate_chain('foo.com', pvtkey)
        cert = DeployableCertificate(chain.decode(), pvtkey_to(key, str))
        assert b'BEGIN CERTIFICATE' in cert.root_pem
        assert b'END CERTIFICATE' in cert.root_pem
        assert cert.root_pem[-1] != b'\n'
        assert b'ROOT CA' in cert.root_der

    def test_pem_chain(self, certificate_chain, pvtkey):
        chain, key = certificate_chain('foo.com', pvtkey)
        cert = DeployableCertificate(chain.decode(), pvtkey_to(key, str))
        str_pem = cert.pem.decode()
        pem_chain_pattern = re.compile(
            r"^-----BEGIN CERTIFICATE-----\n[\S\s]+\n-----END CERTIFICATE-----\n"
            r"-----BEGIN CERTIFICATE-----\n[\S\s]+\n-----END CERTIFICATE-----\n"
            r"-----BEGIN CERTIFICATE-----\n[\S\s]+\n-----END CERTIFICATE-----$"  # no trailing spaces
        )
        match = pem_chain_pattern.match(str_pem)
        if match is None:
            print(str_pem)
            assert False

    def test_der_chain(self, certificate_chain, pvtkey):
        chain, key = certificate_chain('foo.com', pvtkey)
        cert = DeployableCertificate(chain.decode(), pvtkey_to(key, str))
        assert b'foo.com' in cert.der
        assert b'Intermediate CA' in cert.der
        assert b'ROOT CA' in cert.der
        assert cert.der[-1] != b'\n'

    def test_pfx_pkcs12(self, certificate_chain, pvtkey):
        chain, key = certificate_chain('foo.com', pvtkey)
        cert = DeployableCertificate(chain.decode(), pvtkey_to(key, str))
        assert isinstance(cert.pkcs12, bytes)
        assert isinstance(cert.pfx, bytes)

    @pytest.mark.parametrize("keyfmt", ['pkcs1', 'pkcs8'])
    def test_key_formats(self, certificate_chain, pvtkey, keyfmt):
        chain, key = certificate_chain('foo.com', pvtkey)
        cert = DeployableCertificate(chain.decode(), pvtkey_to(key, str))
        if keyfmt == 'pkcs1':
            assert b'RSA' in cert.key_pkcs1
        if keyfmt == 'pkcs8':
            assert b'RSA' not in cert.key_pkcs8


