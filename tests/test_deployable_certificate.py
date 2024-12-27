import pytest
from autossl.certificates import DeployableCertificate
from cryptography.x509 import Certificate
import re


class TestDeployableCertificate:
    def test_init(self, certificate_chain):
        chain = DeployableCertificate(certificate_chain)
        assert isinstance(chain._domain_cert, Certificate)
        assert isinstance(chain._ica_cert, Certificate)
        assert isinstance(chain._root_cert, Certificate)

    def test_domain_cert_properties(self, certificate_chain):
        cert = DeployableCertificate(certificate_chain)
        assert b'BEGIN CERTIFICATE' in cert.domain_pem
        assert b'END CERTIFICATE' in cert.domain_pem
        assert cert.domain_pem[-1] != b'\n'
        assert b'foo.com' in cert.domain_der

    def test_ica_cert_properties(self, certificate_chain):
        cert = DeployableCertificate(certificate_chain)
        assert b'BEGIN CERTIFICATE' in cert.ica_pem
        assert b'END CERTIFICATE' in cert.ica_pem
        assert cert.ica_pem[-1] != b'\n'
        assert b'DigiCert TLS Hybrid ECC SHA384 2020 CA1' in cert.ica_der

    def test_root_cert_properties(self, certificate_chain):
        cert = DeployableCertificate(certificate_chain)
        assert b'BEGIN CERTIFICATE' in cert.root_pem
        assert b'END CERTIFICATE' in cert.root_pem
        assert cert.root_pem[-1] != b'\n'
        assert b'DigiCert Global Root CA' in cert.root_der

    def test_pem_chain(self, certificate_chain):
        cert = DeployableCertificate(certificate_chain)
        str_pem = cert.pem.decode()
        pem_chain_pattern = re.compile(
            r"^-----BEGIN CERTIFICATE-----\n[\S\s]+\n-----END CERTIFICATE-----\n"
            "-----BEGIN CERTIFICATE-----\n[\S\s]+\n-----END CERTIFICATE-----\n"
            "-----BEGIN CERTIFICATE-----\n[\S\s]+\n-----END CERTIFICATE-----$"  # no trailing spaces
        )
        match = pem_chain_pattern.match(str_pem)
        if match is None:
            print(str_pem)
            assert False

    def test_der_chain(self, certificate_chain):
        cert = DeployableCertificate(certificate_chain)
        assert b'foo.com' in cert.der
        assert b'DigiCert TLS Hybrid ECC SHA384 2020 CA1' in cert.der
        assert b'DigiCert Global Root CA' in cert.der
        assert cert.der[-1] != b'\n'
