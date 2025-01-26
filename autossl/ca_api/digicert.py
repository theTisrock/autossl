import requests
from requests.exceptions import HTTPError
from autossl.keygen import CSR
from .ca import DigitalCertificateUses
import os, re
from .ca import CACertificatesInterface
from enum import Enum
from cryptography.x509 import load_pem_x509_csr, DNSName
from cryptography.x509.oid import NameOID, ExtensionOID
import datetime


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
    ROTATION_THRESHOLD = 30
    DUPLICATE_POLICY_CHOICES = DigicertDuplicatePolicies.str_choices()
    DUPLICATE_POLICY = DigicertDuplicatePolicies.PREFER
    CERTIFICATE_USE_CHOICES = DigitalCertificateUses.str_choices()
    CERTIFICATE_USE = DigitalCertificateUses.SERVER_AUTH
    # duplicate_csr = None  # cache the CSR for ordering duplicate certificates

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

    def __init__(self, org_id: int = None, base_url: str = urls.BASE, api_key: str = None):
        """Communicates with DigiCert. Submits CSRs, checks cert status and fetches certificate chain.
        The interface is designed with serverAuth (typical) SSL certificate issuance in mind,
        though it may also handle clientAuth (MTLS) and Code Signing in the future."""
        # AUTH
        self.auth_header: dict = {'X-DC-DEVKEY': api_key}
        if not isinstance(self.auth_header['X-DC-DEVKEY'], str):
            if not os.environ.get('DIGICERT_APIKEY', False): raise ValueError("API key not found.")
            self.auth_header['X-DC-DEVKEY'] = os.environ['DIGICERT_APIKEY']
        self.org_id = org_id
        if org_id is None:
            self.org_id = os.environ.get('DIGICERT_ORGID', None)
            if not self.org_id:
                raise ValueError("Must provide an org_id for digicert")
        # product settings
        self.product_name = self.DEFAULT_PRODUCT_NAME
        self.days_valid = self.SERVERAUTH_MAX_VALIDITY_DAYS
        self.server_platform = 2
        self.payment_method = "balance"
        # urls
        self.base_url = base_url
        self.submit_csr_url = self.urls.SUBMIT_CSR.format(BASE=self.base_url, product_name="{product_name}")
        self.list_orders_url = self.urls.LIST_ORDERS.format(BASE=self.base_url)
        self.duplicate_order_url = self.urls.DUPLICATE_ORDER.format(BASE=self.base_url, order_id="{order_id}")
        self.order_info_url = self.urls.ORDER_INFO.format(BASE=self.base_url, order_id="{order_id}")
        self.download_cert_url = self.urls.DOWNLOAD_CERTIFICATE.format(
            BASE=self.base_url, certificate_id="{certificate_id}"
        )
        # caching
        self.duplicate_csr = None

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
    def order_info(self, order_id: int):
        """Get certificate info for an order_id"""
        headers = {}
        headers.update(self.auth_header)
        headers.update(self.static_headers.contenttype_json)

        response = requests.get(url=self.order_info_url.format(order_id=order_id), headers=headers)
        response.raise_for_status()

        result = response.json()
        return result

    def _list_orders(self, request_headers: dict, query: str = None):
        query = query if query else ''
        url = f"{self.list_orders_url}{query}"
        response = requests.get(url=url, headers=request_headers)
        response.raise_for_status()
        return response

    def list_orders(self, sort: list = None, filters: dict = None):
        """Get orders ordered by date created in descending order.
        Optionally filter on common name, status, date ordered ... etc"""
        # https://dev.digicert.com/en/certcentral-apis/services-api/orders/list-orders.html
        headers = {}
        headers.update(self.auth_header)
        headers.update(self.static_headers.contenttype_json)
        # sort
        _sort_by = set()
        _sort_by.add('-date_created')  # always sort by most recent orders
        if sort is not None:  # enable custom sorting; probably premature optimization?
            for sort_field in sort: _sort_by.add(sort_field)
        _sort_by = list(_sort_by)
        sort_string = "sort="
        sort_string += ",".join(_sort_by)
        # filters
        _filters = set()
        if filters is not None and len(filters) > 0:
            for k, v in filters.items(): _filters.add(f"filters[{k}]={v}")
        filter_string = "&".join(_filters)
        # final query string
        query_string = ""
        if len(filter_string) > 0 or len(sort_string) > 0: query_string = "?"
        query_string += filter_string if len(filter_string) > 0 else ""
        query_string += "&" if len(filter_string) > 0 and len(sort_string) > 0 else ""
        query_string += sort_string if len(sort_string) > 0 else ""
        r = self._list_orders(headers, query=query_string)
        return r.json()

    def list_duplicates(self, order_id: int):
        """Get all of the duplicates for this order.
        Developed for duplicate certificate ordering."""
        headers = dict()
        headers.update(self.auth_header)
        headers.update(self.static_headers.contenttype_json)

        response = requests.get(url=self.duplicate_order_url.format(order_id=order_id), headers=headers)
        response.raise_for_status()

        result = response.json()
        if len(result) == 0: result['certificates'] = list()

        return result

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
        self.duplicate_csr = None
        result = r.json()
        return result

    @staticmethod
    def _select_order_index_for_duplicate(filtered_orders: list):
        """Pass in duplicate order candidates that have been filtered through _filter_eligible_duplicate_orders().
        Return the index in the list of orders with the longest remaining days of validity."""
        if len(filtered_orders) == 0:
            return -1

        selected_index = -1
        max_days_left = filtered_orders[0]['certificate']['days_remaining']
        for idx, order in enumerate(filtered_orders):
            if order['certificate']['days_remaining'] > max_days_left:
                selected_index = idx
                max_days_left = order['certificate']['days_remaining']

        return selected_index

    @staticmethod
    def _filter_eligible_duplicate_orders(orders: list, cert_type: DigitalCertificateUses, csr_sans: list, cn: str):
        """Iterate through orders that we want as a duplicate certificate.
        1) Keep all certificates with status 'issued'
        2) Keep all orders that match the certificate type that we want.
        3) Keep all orders where the SANs match.
        """
        drop_non_issued_orders = lambda order: order['status'] == 'issued'
        drop_non_serverauth = lambda order: order['product']['type'].endswith('ssl_certificate')
        drop_non_clientauth = lambda order: order['product']['type'] == 'client_certificate'
        drop_non_codesign = lambda order: order['product']['type'] == 'code_signing_certificate'

        # don't attempt to duplicate a cert that is not issued already
        issued_orders = [x for x in filter(drop_non_issued_orders, orders)]

        # filter cert type by use
        if cert_type == DigitalCertificateUses.SERVER_AUTH:
            single_cert_type_orders = [x for x in filter(drop_non_serverauth, issued_orders)]
        elif cert_type == DigitalCertificateUses.CLIENT_AUTH:
            single_cert_type_orders = [x for x in filter(drop_non_clientauth, issued_orders)]
        else:  # cert_type == DigitalCertificateUses.CODE_SIGNING:
            single_cert_type_orders = [x for x in filter(drop_non_codesign, issued_orders)]

        # drop certs where sans do not match
        sans_matched_orders = list()
        for order in single_cert_type_orders:
            order_sans = order['certificate']['dns_names']
            # skip the order if they don't have the same number of sans
            # Assumption: a csr will not be provided where the cn and one of the sans match
            if len(order_sans)-1 != len(csr_sans): continue  # digicert puts the cn as a san value, so -1

            # check that sans match between this csr and those on the order we are trying to duplicate
            match = False
            for san in order_sans:
                if san == cn:
                    match = True
                    continue
                sans_match = False if san not in csr_sans else True
                if sans_match is False: break

            if match is True:
                sans_matched_orders.append(order)
        return sans_matched_orders

    def _acquire_duplicate_order_candidate(self, submit_csr_request_data: dict):
        """
        Return the order that matches the CN and SANs of the supplied CSR with the longest validity period.
        Otherwise return None
        """
        cn = submit_csr_request_data['certificate']['common_name']
        sans = submit_csr_request_data['certificate']['dns_names']

        # TODO list all orders for this common_name within a timeframe
        past_date = datetime.datetime.now() - (
                datetime.timedelta(days=self.SERVERAUTH_MAX_VALIDITY_DAYS) - datetime.timedelta(days=self.ROTATION_THRESHOLD)
        )
        past_date_str = past_date.strftime('%Y-%m-%dT00:00:00')
        recent_date = datetime.datetime.now()
        recent_date_str = recent_date.strftime('%Y-%m-%dT23:59:59')
        filters = {
            'common_name': cn, 'status': 'issued', 'date_created': f"{past_date_str}...{recent_date_str}"
        }
        result = self.list_orders(filters=filters)

        if result.get('orders', None) is None: result.update({'orders': []})  # virtualize zero orders with empty list

        filtered_candidates = DigicertCertificates._filter_eligible_duplicate_orders(
            result['orders'], DigicertCertificates.CERTIFICATE_USE, sans, cn
        )

        selected = self._select_order_index_for_duplicate(filtered_candidates)
        selected_order = filtered_candidates[selected] if selected > -1 else None
        return selected_order

    def _submit_csr_for_duplicate(self, request_data: dict, request_headers: dict):
        """Attempt to order a duplicate certificate, if one exists."""
        order = self._acquire_duplicate_order_candidate(request_data)
        if order is None:
            print('duplicate order not found')
            return order

        url = self.duplicate_order_url.format(order_id=order['id'])
        response = requests.post(url=url, headers=request_headers, json=request_data)
        response.raise_for_status()
        # cache so that we can select the correct duplicate for download later on
        self.duplicate_csr = request_data['certificate']['csr']

        result = response.json()
        return result

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
        """When the user supplies a CSR that is not an instance of autossl.keygen.CSR and instead str,
        extract the fields from the user suppleid CSR so that we can make a web request for a certificate."""
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
        """The main CSR submission controller/driver. Controls new and duplicate certificate ordering."""
        headers = {}
        headers.update(self.auth_header)
        headers.update(self.static_headers.contenttype_json)
        headers.update(self.static_headers.accept_json)

        required_csr_fields = {'common_name': None, 'dns_names': None, 'signature_hash': None, 'csr': None}
        csr_txt = None
        # CSR field extraction
        if isinstance(pem_csr, bytes):
            pem_csr = pem_csr.decode(encoding='utf-8')
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
            self.duplicate_csr = None  # clear the current CSR since the request failed
            print("Failed to fetch a duplicate certificate from Digicert.")
            return None
        if duplicate_policy in [DigicertDuplicatePolicies.NEW, DigicertDuplicatePolicies.PREFER]:  # new order attempt
            result = self._submit_csr(request_data, headers)

        order_id = result['id']
        return order_id

    def certificate_is_issued(self, order_id: int):
        """Check that the certificate for the given order id has been issued."""
        results = self.order_info(order_id)
        assert order_id == results['id']
        print(f"DigiCert order {order_id} returned a status of {results['status']}.")
        return results['status'] == 'issued'

    def _fetch_pem_certificate_chain(self, certificate_id: int, request_headers: dict):
        url = self.download_cert_url.format(certificate_id=certificate_id)

        response = requests.get(url=url, headers=request_headers)
        try:
            response.raise_for_status()
        except HTTPError as httperror:
            if response.status_code in [403, 404]:
                print(f"Failed to download the certificate. certificate_id:{certificate_id}")
                raise response.raise_for_status()

        whole_pem = response.content.decode(encoding='utf-8')
        fullchain_pem_pattern = re.compile(r"^(-----BEGIN CERTIFICATE-----\n[\S\s]+\n-----END CERTIFICATE-----)\n"
                                           r"(-----BEGIN CERTIFICATE-----\n[\S\s]+\n-----END CERTIFICATE-----)\n"
                                           r"(-----BEGIN CERTIFICATE-----\n[\S\s]+\n-----END CERTIFICATE-----)\n*$")
        match = re.match(fullchain_pem_pattern, whole_pem)
        try:  # make sure we have all parts accounted for before we deliver the cert components
            assert match is not None
        except AssertionError:
            raise ValueError("One or more certificates in the chain provided by DigiCert Inc may not be present.")

        domain, ica, root = match.groups()
        domain = domain.strip()
        ica = ica.strip()
        root = root.strip()

        pem_cert_chain_components = (
            domain.encode(encoding='utf-8'),
            ica.encode(encoding='utf-8'),
            root.encode(encoding='utf-8'),
        )

        return pem_cert_chain_components

    def _select_duplicate(self, order_id: int):
        """During submit_csr, if a duplicate was ordered, it has been cached in this Digicert client instance under
        thisinstance.duplicate_csr
        After the duplicate is ordered and ready for download, the CSR used to order the cert (the cached CSR)
        is used to select the properly matching certificate."""
        print("checking for duplicates that matches the cached CSR.")
        duplicates = self.list_duplicates(order_id)  # contains list of dupes with matching CSR at the end.

        certificate_id = None
        found = False
        for cert in duplicates['certificates']:
            if cert['csr'] == self.duplicate_csr:
                print("Found CSR-matched duplicate.")
                found = True
                certificate_id = cert['id']  # selects cert id 123321
                break
        if not found: print("duplicate not found.")

        self.duplicate_csr = None
        return certificate_id  # return cert id

    def fetch_certificate(self, order_id: int):
        """Download the full digital certificate chain without leading or trailing white space.
        Returned as tuple(bytes(domain), bytes(ica), bytes(root))"""
        headers = dict()
        headers.update(self.static_headers.accept_zip)
        headers.update(self.static_headers.contenttype_json)
        headers.update(self.auth_header)

        order = self.order_info(order_id)  # calls order 123456
        certificate_id = self._select_duplicate(order_id)
        if certificate_id is None:
            certificate_id = order['certificate']['id']

        print("fetching the certificate")
        chain = self._fetch_pem_certificate_chain(certificate_id, headers)  # downloads cert id 123321
        return chain
