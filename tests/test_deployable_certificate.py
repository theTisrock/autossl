import pytest
from autossl.certificates import DeployableCertificate
from cryptography.x509 import Certificate


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
