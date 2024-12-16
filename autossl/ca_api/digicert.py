from .ca import DigitalCertificateUses
import os
from .ca import CACertificatesInterface
from enum import Enum


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
            if not os.environ.get('DIGICERT_APIKEY', False):
                raise ValueError("API key not found.")
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
    def submit_certificate_request(self, csr):
        pass

    def certificate_is_issued(self, id_):
        pass

    def fetch_certificate(self, id_):
        pass
