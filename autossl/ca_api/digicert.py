import pprint
import requests
from requests.exceptions import HTTPError
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

    def __init__(self, org_id: int, base_url: str = urls.BASE, api_key: str = None):
        """Communicates with DigiCert. Submits CSRs, checks cert status and fetches certificate chain.
        The interface is designed with serverAuth (typical) SSL certificate issuance in mind,
        though it may also handle clientAuth (MTLS) and Code Signing in the future."""
        auth_header_template = "{api_key}"
        # AUTH
        self.auth_header: dict = {'X-DC-DEVKEY': api_key}
        if not isinstance(self.auth_header['X-DC-DEVKEY'], str):
            if not os.environ.get('DIGICERT_APIKEY', False): raise ValueError("API key not found.")
            self.auth_header['X-DC-DEVKEY'] = os.environ['DIGICERT_APIKEY']
        self.org_id = org_id

        # product settings
        self.product_name = self.DEFAULT_PRODUCT_NAME
        self.days_valid = self.SERVERAUTH_MAX_VALIDITY_DAYS
        self.server_platform = 2
        self.payment_method = "balance"

        # urls
        self.base_url = base_url
        self.submit_csr_url = self.urls.SUBMIT_CSR.format(BASE=self.base_url, product_name="{product_name}")
        self.list_orders_url = self.urls.LIST_ORDERS.format(BASE=self.base_url)

    def __repr__(self):
        return f"<DigiCert Cert Client: '{self.base_url}'>"


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
    def _list_orders(self, request_headers: dict, query: str = None):
        query = query if query else ''
        url = f"{self.list_orders_url}{query}"
        response = requests.get(url=url, headers=request_headers)
        response.raise_for_status()
        return response

    def list_orders(self):
        """Get orders ordered by date created in descending order. Optionally filter on common_name, and date_created."""
        headers = {}
        headers.update(self.auth_header)
        headers.update(self.static_headers.contenttype_json)
        r = self._list_orders(headers)
        return r.json()

    def _submit_csr(self, request_data: dict, request_headers: dict):
        """Concerns certificate request submissions that do not require duplicate certificates.
        Submit the CSR to DigiCert for signing. Does not acquire the SSL certificate itself.
        To do that, see 'fetch_certificate'.
        Returns the entire response which contains the order_id.
        Use the returned order_id to download the certificate or check its status."""
        product_name = self.product_name
        url = self.submit_csr_url.format(product_name=product_name)

        r = requests.post(url=url, headers=request_headers, json=request_data)
        r.raise_for_status()
        try:
            r.raise_for_status()
        except HTTPError as http_error:
            print(r.text)
            r.raise_for_status()

        # this is not a duplicate request, so clobber the previous csr so that downstream certificate download
        # doesn't try to fetch a potentially non-existent duplicate
        DigicertCertificates.duplicate_csr = None
        result = r.json()
        return result

    def _submit_csr_for_duplicate(self, request_data: dict, request_headers: dict):
        # in order to order a duplicate we must be able to
        # TODO list_orders
        # TODO filter eligible duplicate orders
        # TODO select an order index for duplicate ordering
        # TODO return a selected order from a collection of possible duplicates
        pass

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
        required_fields['common_name'] = _cn
        required_fields['dns_names'] = _sans
        required_fields['signature_hash'] = _csr.signature_hash_algorithm.name
        return required_fields

    def submit_certificate_request(self, pem_csr: str | CSR):
        headers = {}
        headers.update(self.auth_header)
        headers.update(self.static_headers.contenttype_json)
        headers.update(self.static_headers.accept_json)

        required_csr_fields = {'common_name': None, 'dns_names': None, 'signature_hash': None, 'csr': None}
        csr_txt = None
        # CSR field extraction
        if isinstance(pem_csr, str):
            csr_txt = pem_csr
            if self._is_valid_user_csr(pem_csr): required_csr_fields = self._extract_user_supplied_csr_fields(pem_csr)
        elif isinstance(pem_csr, CSR):
            csr_txt = pem_csr.pem.decode(encoding='utf-8')
            required_csr_fields['dns_names'] = pem_csr.get_san_names()
            required_csr_fields['common_name'] = pem_csr.common_name
            required_csr_fields['signature_hash'] = pem_csr.signed_csr.signature_hash_algorithm.name
        # BUILD REQUEST DATA
        request_data = {
            'certificate': {
                'common_name': required_csr_fields['common_name'],
                'dns_names': required_csr_fields['dns_names'],
                'signature_hash': required_csr_fields['signature_hash'],
                'cert_validity': {'days': self.days_valid},
                'csr': csr_txt,
                'server_platform': {'id': self.server_platform}
            },
            'organization': {'id': self.org_id},
            'payment_method': self.payment_method
        }
        # ORDER NEW OR ORDER DUPLICATE according to duplicate policy on the client
        result = None
        duplicate_policy = DigicertCertificates.get_duplicate_policy()
        if duplicate_policy in [DigicertDuplicatePolicies.REQUIRE, DigicertDuplicatePolicies.PREFER]:
            result = self._submit_csr_for_duplicate(request_data, headers)
        if duplicate_policy == DigicertDuplicatePolicies.REQUIRE and result is None:
            DigicertCertificates.duplicate_csr = None  # clear the current CSR since the request failed
            print("Failed to fetch a duplicate certificate from Digicert.")
            return None
        if duplicate_policy in [DigicertDuplicatePolicies.NEW, DigicertDuplicatePolicies.PREFER]:  # new order attempt
            result = self._submit_csr(request_data, headers)

        order_id = result['id']
        return order_id

    def certificate_is_issued(self, id_):
        pass

    def fetch_certificate(self, id_):
        pass
