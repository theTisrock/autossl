from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from .pvtkey import RSAPrivateKey

class CSR(object):

    def __init__(self, pvtkey: RSAPrivateKey, common_name: str):
        self._pvt_key = pvtkey._native_key_object
        self.builder = x509.CertificateSigningRequestBuilder()
        self.common_name = common_name
        self.organization = None
        self.organizational_unit = None
        self.locality = None
        self.state = None
        self.country = None
        self.email = None
        self._sans = list()

    def __repr__(self):
        return f"<CSR cn:{self.common_name} sans:{len(self.get_san_names())} key:rsa{self._pvt_key.key_size}-bit>"

    @property
    def common_name(self):
        """String representation of destined for the certificate; used for humans mostly."""
        return self._cn.value

    @common_name.setter
    def common_name(self, cn: str):
        """The object representation destined for certificate to be used for final construction of CSR."""
        self._cn = x509.NameAttribute(NameOID.COMMON_NAME, u"{cn}".format(cn=cn))

    @property
    def sans(self):
        """Get a copy of the cryptography SANs objects."""
        _sans = list()
        if len(self._sans) == 0: return _sans
        for s in self._sans: _sans.append(s['object'])
        return _sans

    @sans.setter
    def sans(self, alt_names: list):
        """Replace the cryptography and string versions of the SANS and drop duplicates."""
        if not isinstance(alt_names, list):
            raise ValueError("When setting multiple SANs at once, a list must be provided.")
        self._sans = list()
        for san in alt_names:
            self.add_san(san)


    def add_san(self, san: str):
        """Add one SAN at a time while restricting duplicates."""
        if self._sans is None: self._sans = list()
        if san is None: return
        if san in self.get_san_names(): return
        self._sans.append(
            {'str': f"{san}",
             'object': x509.DNSName(u"{san}".format(san=san))}
        )

    def get_san_names(self):
        """Get a human readable SANS list"""
        return [san['str'] for san in self._sans]


    @property
    def organization(self):
        """String representation of destined for the certificate; used for humans mostly."""
        return self._org.value

    @organization.setter
    def organization(self, org_name: str):
        """The object representation destined for certificate to be used for final construction of CSR."""
        self._org = x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"{org}".format(org=org_name)) if org_name else None

    @property
    def organizational_unit(self):
        """String representation of destined for the certificate; used for humans mostly."""
        return self._ou.value

    @organizational_unit.setter
    def organizational_unit(self, ou: str):
        """The object representation destined for certificate to be used for final construction of CSR."""
        self._ou = x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"{ou}".format(ou=ou)) if ou else None

    @property
    def locality(self):
        """String representation of destined for the certificate; used for humans mostly."""
        return self._locality.value

    @locality.setter
    def locality(self, place: str):
        """The object representation destined for certificate to be used for final construction of CSR."""
        self._locality = x509.NameAttribute(NameOID.LOCALITY_NAME, u"{place}".format(place=place)) if place else None

    @property
    def state(self):
        """String representation of destined for the certificate; used for humans mostly."""
        return self._state.value

    @state.setter
    def state(self, state: str):
        """The object representation destined for certificate to be used for final construction of CSR."""
        self._state = x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"{st}".format(st=state)) if state else None

    @property
    def country(self):
        """String representation of destined for the certificate; used for humans mostly."""
        return self._country.value

    @country.setter
    def country(self, country: str):
        """The object representation destined for certificate to be used for final construction of CSR."""
        self._country = x509.NameAttribute(NameOID.COUNTRY_NAME, u"{c}".format(c=country)) if country else None

    @property
    def email(self):
        """String representation of destined for the certificate; used for humans mostly."""
        return self._email.value

    @email.setter
    def email(self, email: str):
        """The object representation destined for certificate to be used for final construction of CSR."""
        self._email = x509.NameAttribute(NameOID.EMAIL_ADDRESS, u"{email}".format(email=email)) if email else None
