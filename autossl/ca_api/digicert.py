from idlelib.iomenu import encoding

from autossl.keygen import CSR
from .ca import DigitalCertificateUses
import os
from .ca import CACertificatesInterface
from enum import Enum
from cryptography.x509 import load_pem_x509_csr, DNSName
from cryptography.x509.oid import NameOID, ExtensionOID


class DigicertDuplicatePolicies(Enum):
    PREFER = 1
    REQUIRE = 2
    NEW = 3

    @classmethod
    def str_choices(cls):
        return [e.name for e in list(cls)]

class DigicertCertificates(CACertificatesInterface):
    """A client that interacts with Digicert to
    1) request a certificate
    2) check the status of a certificate
    3) download the certificate
    Not to be used for any other purpose."""
    DEFAULT_PRODUCT_NAME = 'ssl_basic'
    SERVERAUTH_MAX_VALIDITY_DAYS = 396
    DUPLICATE_POLICY_CHOICES = DigicertDuplicatePolicies.str_choices()
    DUPLICATE_POLICY = DigicertDuplicatePolicies.PREFER
    CERTIFICATE_USE_CHOICES = DigitalCertificateUses.str_choices()
    CERTIFICATE_USE = DigitalCertificateUses.SERVER_AUTH
    duplicate_csr = None  # cache the CSR for ordering duplicate certificates

    class urls:
        BASE = "https://www.digicert.com/services/v2/"
        DOWNLOAD_CERTIFICATE = "{BASE}certificate/{certificate_id}/download/format/pem_all"  # 2 is apache
        SUBMIT_CSR = "{BASE}order/certificate/{product_name}"
        LIST_ORDERS = "{BASE}order/certificate"
        ORDER_INFO = "{BASE}order/certificate/{order_id}"
        DUPLICATE_ORDER = "{BASE}order/certificate/{order_id}/duplicate"

    class static_headers:
        accept_json = {"Accept": "application/json"}
        accept_zip = {'Accept': "application/zip"}
        contenttype_urlencoded = {"Content-Type": "application/x-www-form-urlencoded"}
        contenttype_json = {"Content-Type": "application/json"}

    def __init__(self, base_url: str = urls.BASE, api_key: str = None):
        """Communicates with DigiCert. Submits CSRs, checks cert status and fetches certificate chain.
        The interface is designed with serverAuth (typical) SSL certificate issuance in mind,
        though it may also handle clientAuth (MTLS) and Code Signing in the future."""
        auth_header_template = "{api_key}"

        # API KEY
        self.auth_header: dict = {'X-DC-DEVKEY': api_key}
        if not isinstance(self.auth_header['X-DC-DEVKEY'], str):
            if not os.environ.get('DIGICERT_APIKEY', False): raise ValueError("API key not found.")
            self.auth_header['X-DC-DEVKEY'] = os.environ['DIGICERT_APIKEY']

        # product settings
        self.product_name = self.DEFAULT_PRODUCT_NAME
        self.days_valid = self.SERVERAUTH_MAX_VALIDITY_DAYS

        # urls
        self.base_url = base_url
        self.submit_csr_url = self.urls.SUBMIT_CSR.format(BASE=self.base_url, product_name="{product_name}")


    # PRODUCT SETTINGS
    def set_product_name(self, name: str):
        """Set the digicert digital certificate product name."""
        self.product_name = name

    def set_days_valid(self, days: int):
        """Set the validity period as amount of days.
        server_auth certificates have an CA/B forum mandated max validity of 397 days."""
        self.days_valid = days

    @classmethod
    def set_duplicate_policy(cls, policy: str):
        """Set the duplicate ordering policy:
        'prefer': attempts to order a duplicate certificate from an existing order.
                If it fails, a new certificate will be ordered.
        'require': only orders a duplicate certificate from an existing order.
        'new': places a new order for a certificate and does not check for duplicates.
        """
        if policy.upper() not in cls.DUPLICATE_POLICY_CHOICES:
            raise ValueError(
                f"Invalid duplicate policy. Selection: '{policy}' Choices: {cls.DUPLICATE_POLICY_CHOICES}"
            )
        cls.DUPLICATE_POLICY = getattr(DigicertDuplicatePolicies, policy.upper())

    @classmethod
    def get_duplicate_policy(cls):
        return cls.DUPLICATE_POLICY

    @classmethod
    def set_certificate_functions_as(cls, certificate_type: str):
        """Select the type of certificate that is ordered from DigiCert.
        'server_auth': a conventional SSL certificate used by the client to validate the server.
        'client_auth': a mutual TLS certificate used by the server to validate the client.
        'code_signing': used to validate a digital signature associated a dataset, typically software or documents."""
        if certificate_type.upper() not in cls.CERTIFICATE_USE_CHOICES:
            raise ValueError(
                f"Invalid certificate type. Selection: '{certificate_type}' Choices: {cls.CERTIFICATE_USE_CHOICES}"
            )
        cls.CERTIFICATE_USE = getattr(DigitalCertificateUses, certificate_type.upper())

    # API CALLS
    def _submit_certificate_request(self, csr: str, cn: str, sans: list, sighash: str, ):
        """Concerns certificate request submissions that do not require duplicate certificates.
        Submit the CSR to DigiCert for signing. Does not acquire the SSL certificate itself.
        To do that, see 'fetch_certificate'.
        Returns the entire response which contains the order_id.
        Use the returned order_id to download the certificate or check its status."""
        headers = {}
        headers.update(self.auth_header)
        headers.update(self.static_headers.contenttype_json)
        headers.update(self.static_headers.accept_json)

        product_name = self.product_name
        url = self.submit_csr_url.format(product_name=product_name)

        data = {
            "certificate": {
                "common_name": "example.com",
                "dns_names": [
                    "sub.example.com",
                    "app.example.com"
                ],
                "csr": "<csr>",
                "signature_hash": "sha256",
                "server_platform": {
                    "id": 2
                }
            },
            "auto_renew": 0,
            "auto_reissue": 0,
            "organization": {
                "id": 123456,
                "contacts": [
                    {
                        "contact_type": "organization_contact",
                        "user_id": 565611
                    },
                    {
                        "contact_type": "technical_contact",
                        "first_name": "Jill",
                        "last_name": "Valentine",
                        "job_title": "STAR Member",
                        "telephone": "8017019600",
                        "email": "jill.valentine@digicert.com"
                    }
                ]
            },
            "order_validity": {
                "days": 397
            },
            "payment_method": "balance"
        }

    def _is_valid_user_csr(self, csr: str):
        header = '-----BEGIN CERTIFICATE REQUEST-----'
        footer = '-----END CERTIFICATE REQUEST-----'
        try:
            assert csr.startswith(header)
            assert csr.endswith(footer)
        except AssertionError:
            raise AssertionError("Either the header or footer of the CSR is invalid. "
                                 "Ensure it contains no trailing or leading white space characters.")
        return True

    @classmethod
    def _extract_user_supplied_csr_fields(cls, csr: str):
        required_fields = dict()
        _csr = load_pem_x509_csr(csr.encode(encoding='utf-8'))
        _cn = _csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        ext = _csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        _sans = ext.value.get_values_for_type(DNSName)
        required_fields['cn'] = _cn
        required_fields['sans'] = _sans
        required_fields['signature_hash'] = _csr.signature_hash_algorithm.name
        return required_fields






    # def submit_certificate_request(self, pem_csr: str | CSR):
    #     required_csr_fields = {'cn': None, 'dns_names': None, 'signature_hash': None}
    #     csr_txt = None
    #     if isinstance(pem_csr, str):
    #         # TODO retain the original text of the CSR
    #         csr_txt = pem_csr
    #         # TODO validate the text CSR
    #         if self._is_valid_user_csr(pem_csr):
    #             # TODO load the csr
    #             # TODO extract required fields
    #             self._extract_user_supplied_csr_fields(_csr)
    #
    #         # TODO submit the csr to digicert
    #         # TODO get the order id
    #         pass
    #     elif isinstance(pem_csr, CSR):
    #         # TODO extract required csr fields
    #         # TODO submit the csr to digicert
    #         # TODO get the order id
    #         pass





    def certificate_is_issued(self, id_):
        pass

    def fetch_certificate(self, id_):
        pass
