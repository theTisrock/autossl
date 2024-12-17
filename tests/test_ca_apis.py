import pytest
from autossl.ca_api import DigicertCertificates
from autossl.keygen import CSR, RSAPrivateKey
import pprint

TEST_BASE_URL = 'http://localhost:3001/'



class TestDigicertCertificatesClient(object):

    @pytest.mark.parametrize("with_sans", [True, False])
    def test_extract_user_supplied_csr(self, with_sans, csr_without_sans, csr_with_sans):
        if with_sans:
            results = DigicertCertificates._extract_user_supplied_csr_fields(csr_with_sans)
            pprint.pprint(results)
            assert results['dns_names'] == ['www.foo.com', 'bar.com', 'www.bar.com']
        else:
            results = DigicertCertificates._extract_user_supplied_csr_fields(csr_without_sans)
            pprint.pprint(results)
            assert results['dns_names'] == []
        if not results:
            assert False
        pprint.pprint(results)
        assert results['common_name'] == 'foo.com'
        assert results['signature_hash'] == 'sha256'

    def test_list_orders(self, list_orders):
        digicert = DigicertCertificates(123, TEST_BASE_URL, api_key='_')
        actual = digicert.list_orders()
        assert actual['orders'] == list_orders['orders']


    @pytest.mark.parametrize("cn,sans", [
        ('foo.com', ['www.foo.com', 'bar.com', 'www.bar.com'], ),
        ('foo.com', [], ),
    ])
    def test_submit_csr(self, cn, sans):
        expected = 123456  # mockoon: digicert_api.json
        digicert = DigicertCertificates(123, TEST_BASE_URL, api_key='_')
        csr = CSR(RSAPrivateKey(), 'foo.com')
        for s in sans:
            csr.add_san(s)
        csr.finalize()
        actual = digicert.submit_certificate_request(csr)
        pprint.pprint(csr)
        assert actual == expected

    def test_check_certificate_issuance_status(self):
        pass

    def test_certificate_download(self):
        pass
