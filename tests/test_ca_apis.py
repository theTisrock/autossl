import pytest
from autossl.ca_api import DigicertCertificates
from autossl.keygen import CSR, RSAPrivateKey
import pprint
from freezegun import freeze_time

TEST_BASE_URL = 'http://localhost:3001/'


@freeze_time("2024-12-17")
class TestDigicertCertificatesClient(object):

    @pytest.mark.parametrize("with_sans", [True, False])
    def test_extract_user_supplied_csr(self, with_sans, csr_without_sans, csr_with_sans):
        """Test that the CSR fields are extracted in case the user opts to submit a CSR in text form
        as opposed to using autossl.keygen.CSR"""
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
        """Test listing orders (without duplicates)."""
        # https://dev.digicert.com/en/certcentral-apis/services-api/orders/list-orders.html
        digicert = DigicertCertificates(123, TEST_BASE_URL, api_key='_')
        actual = digicert.list_orders()
        print(actual)
        assert actual['orders'] == list_orders['orders']

    @pytest.mark.parametrize("order_id,cn", [(123456, 'foo.com', )])
    def test_order_info(self, order_id, cn):
        digicert = DigicertCertificates(123, TEST_BASE_URL, api_key='_')
        actual = digicert.order_info(str(order_id))
        assert actual['id'] == order_id
        assert actual['certificate']['common_name'] == cn
        assert cn in actual['certificate']['dns_names']

    # MAIN API
    @pytest.mark.parametrize("cn,sans,csr_type,dupe_policy,expected_order", [
        ('foo.com', ['www.foo.com', 'bar.com', 'www.bar.com'], CSR, 'new', 123456, ),  # autossl supplied csr w/ sans
        ('foo.com', [], CSR, 'new', 123456, ),  # autossl supplied csr w/o sans
        ('foo.com', [], str, 'new', 123456, ),  # try user supplied csr
        ('foo.com', [], CSR, 'require', 123459, ),  # force a duplicate order
    ])
    def test_submit_csr(self, cn, sans, csr_type, csr_without_sans, dupe_policy, expected_order):
        # mockoon: digicert_api.json
        """Test both submitting csr for a new certificate and for a duplicate certificate."""
        digicert = DigicertCertificates(123, TEST_BASE_URL, api_key='_')
        digicert.set_duplicate_policy(dupe_policy)

        csr = csr_without_sans
        if isinstance(csr_type, CSR):
            csr = CSR(RSAPrivateKey(), 'foo.com')
            for s in sans:
                csr.add_san(s)
            csr.finalize()

        actual = digicert.submit_certificate_request(csr)
        assert actual == expected_order

    @pytest.mark.parametrize("order_id,expected", [(123456, True, ), (123457, False, )])
    def test_is_issued(self, order_id, expected):
        """Test that the certificate has been issued"""
        digicert = DigicertCertificates(123, TEST_BASE_URL, api_key='_')
        actual = digicert.certificate_is_issued(order_id)
        assert actual == expected

    def test_download(self):
        """Test downloading the certificate chain."""
        pass
