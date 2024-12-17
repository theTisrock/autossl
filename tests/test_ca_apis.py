import pytest
from autossl.ca_api import DigicertCertificates
from autossl.keygen import CSR, RSAPrivateKey


class TestDigicertCertificatesClient(object):

    @pytest.mark.parametrize("with_sans", [True, False])
    def test_extract_user_supplied_csr(self, with_sans, csr_without_sans, csr_with_sans):
        if with_sans:
            results = DigicertCertificates._extract_user_supplied_csr_fields(csr_with_sans)
            assert results['sans'] == ['www.foo.com', 'bar.com', 'www.bar.com']
        else:
            results = DigicertCertificates._extract_user_supplied_csr_fields(csr_without_sans)
            assert results['sans'] == []
        if not results:
            assert False

        assert results['cn'] == 'foo.com'
        assert results['signature_hash'] == 'sha256'

    def test_submit_csr(self):
        pass

    def test_check_certificate_issuance_status(self):
        pass

    def test_certificate_download(self):
        pass
