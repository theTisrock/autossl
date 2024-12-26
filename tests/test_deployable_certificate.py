import pytest
from autossl.certificates import DeployableCertificate
from cryptography.x509 import Certificate


def test_deployable_certificate_init_(certificate_chain):
    chain = DeployableCertificate(certificate_chain)
    assert isinstance(chain._domain_cert, Certificate)
    assert isinstance(chain._ica_cert, Certificate)
    assert isinstance(chain._root_cert, Certificate)
