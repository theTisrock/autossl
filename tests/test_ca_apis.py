import pytest
from autossl.ca_api import DigicertCertificates
from autossl.keygen import CSR, RSAPrivateKey


class TestDigicertCertificatesClient(object):


    @pytest.mark.parametrize("tyype", [str, CSR])
    def test_valid_csr_before_submit(self, tyype, foo_dot_com_csr_str):
        csr = None
        if tyype.__class__.__name__ == CSR.__class__.__name__:
            csr = CSR(RSAPrivateKey(), 'foo.com')
            csr.finalize()
        elif type.__class__.__name__ == str.__class__.__name__:
            csr = foo_dot_com_csr_str
        client = DigicertCertificates(api_key='x')
        csr_txt = client._validate_csr(csr)
        assert isinstance(csr_txt, str)
        assert csr_txt.startswith('-----BEGIN CERTIFICATE REQUEST-----')
        assert csr_txt.endswith('-----END CERTIFICATE REQUEST-----')


    def test_submit_csr(self):
        pass

    def test_check_certificate_issuance_status(self):
        pass

    def test_certificate_download(self):
        pass
