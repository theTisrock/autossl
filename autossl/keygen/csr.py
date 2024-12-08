from idlelib.iomenu import encoding

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from .pvtkey import RSAPrivateKey
import pprint

class CSR(object):

    ENCODINGS = {'pem': serialization.Encoding.PEM, 'der': serialization.Encoding.DER}

    def __init__(self, pvtkey: RSAPrivateKey, common_name: str, critical: bool = False, out_encoding: str = 'pem'):
        self.is_signed = False
        self._pvtkey_fmt = pvtkey.selected_format
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
        self.critical = critical
        self._pem = None
        self._der = None
        self._out = None
        self.selected_encoding = out_encoding
        self._public_key = None

    def __str__(self):
        csr = {
            'cn': self.common_name,
            'sans': self.get_san_names(),
            'o': self.organization,
            'ou': self.organizational_unit,
            'st': self.state,
            'c': self.country,
            'signed': self.is_signed,
            'pem': self.pem.decode(encoding='utf-8') if self.pem else self.pem,
            'pubkey': self.public_key.decode(encoding='utf-8') if self.public_key else self.public_key
        }
        return pprint.pformat(csr)

    def __repr__(self):
        return f"<CSR cn:{self.common_name} sans:{len(self.get_san_names())} key:rsa{self._pvt_key.key_size}-bit>"

    def _do_not_modify_fields(self):
        if self.is_signed:
            print("The CSR has already been signed. Further modification is not allowed.")
        return self.is_signed

    @property
    def common_name(self):
        """String representation of destined for the certificate; used for humans mostly."""
        return self._cn.value

    @common_name.setter
    def common_name(self, cn: str):
        """The object representation destined for certificate to be used for final construction of CSR."""
        if self._do_not_modify_fields(): return
        self._cn = x509.NameAttribute(NameOID.COMMON_NAME, u"{cn}".format(cn=cn))
        return

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
        if self._do_not_modify_fields(): return
        if not isinstance(alt_names, list):
            raise ValueError("When setting multiple SANs at once, a list must be provided.")
        self._sans = list()
        for san in alt_names:
            self.add_san(san)
        return

    def add_san(self, san: str):
        """Add one SAN at a time while restricting duplicates."""
        if self._do_not_modify_fields(): return
        if self._sans is None: self._sans = list()
        if san is None: return
        if san in self.get_san_names(): return
        self._sans.append(
            {'str': f"{san}",
             'object': x509.DNSName(u"{san}".format(san=san))}
        )
        return

    def get_san_names(self):
        """Get a human readable SANS list"""
        return [san['str'] for san in self._sans]

    @property
    def organization(self):
        """String representation of destined for the certificate; used for humans mostly."""
        return '' if not self._org else self._org.value

    @organization.setter
    def organization(self, org_name: str):
        """The object representation destined for certificate to be used for final construction of CSR."""
        if self._do_not_modify_fields(): return
        self._org = x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"{org}".format(org=org_name)) if org_name else None
        return

    @property
    def organizational_unit(self):
        """String representation of destined for the certificate; used for humans mostly."""
        return '' if not self._ou else self._ou.value

    @organizational_unit.setter
    def organizational_unit(self, ou: str):
        """The object representation destined for certificate to be used for final construction of CSR."""
        if self._do_not_modify_fields(): return
        self._ou = x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"{ou}".format(ou=ou)) if ou else None
        return

    @property
    def locality(self):
        """String representation of destined for the certificate; used for humans mostly."""
        return '' if not self._locality else self._locality.value

    @locality.setter
    def locality(self, place: str):
        """The object representation destined for certificate to be used for final construction of CSR."""
        if self._do_not_modify_fields(): return
        self._locality = x509.NameAttribute(NameOID.LOCALITY_NAME, u"{place}".format(place=place)) if place else None
        return

    @property
    def state(self):
        """String representation of destined for the certificate; used for humans mostly."""
        return '' if not self._state else self._state.value

    @state.setter
    def state(self, state: str):
        """The object representation destined for certificate to be used for final construction of CSR."""
        if self._do_not_modify_fields(): return
        self._state = x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"{st}".format(st=state)) if state else None
        return

    @property
    def country(self):
        """String representation of destined for the certificate; used for humans mostly."""
        return '' if not self._country else self._country.value

    @country.setter
    def country(self, country: str):
        """The object representation destined for certificate to be used for final construction of CSR."""
        if self._do_not_modify_fields(): return
        self._country = x509.NameAttribute(NameOID.COUNTRY_NAME, u"{c}".format(c=country)) if country else None

    @property
    def email(self):
        """String representation of destined for the certificate; used for humans mostly."""
        return '' if not self._email else self._email.value

    @email.setter
    def email(self, email: str):
        """The object representation destined for certificate to be used for final construction of CSR."""
        if self._do_not_modify_fields(): return
        self._email = x509.NameAttribute(NameOID.EMAIL_ADDRESS, u"{email}".format(email=email)) if email else None

    @property
    def pem(self):
        return None if not self.is_signed else self._pem

    @pem.setter
    def pem(self, _):
        print("Setting the output property explicitly is not allowed.")
        return

    @property
    def out(self):
        return None if not self.is_signed else self._out

    @out.setter
    def out(self, _):
        print("Setting the output property explicitly is not allowed.")
        return

    @property
    def der(self):
        return None if not self.is_signed else self._der

    @der.setter
    def der(self, _):
        print("Setting the output property explicitly is not allowed.")
        return

    @property
    def public_key(self):
        return None if not self._public_key else self._public_key

    @public_key.setter
    def public_key(self, _):
        print("Setting the output property explicitly is not allowed.")
        return

    def finalize(self):
        """Glue the CSR components together, sign them, and store the PEM encoding in bytes."""
        basic_fields = [self._cn]
        if self._org: basic_fields.append(self._org)
        if self._ou: basic_fields.append(self._ou)
        if self._locality: basic_fields.append(self._locality)
        if self._state: basic_fields.append(self._state)
        if self._country: basic_fields.append(self._country)
        if self._email: basic_fields.append(self._email)
        # basic fields
        self.builder = self.builder.subject_name(x509.Name(basic_fields))
        # extensions
        self.builder = self.builder.add_extension(x509.SubjectAlternativeName(self.sans), critical=self.critical)
        # sign
        signed_csr = self.builder.sign(self._pvt_key, hashes.SHA256())
        self.is_signed = True
        # make available
        _out = signed_csr.public_bytes(CSR.ENCODINGS[self.selected_encoding])
        self._out = _out
        # remove white space chars from the end of an ascii-based result
        if self.selected_encoding == 'pem':
            self._out = _out[:-1]
        self._pem = signed_csr.public_bytes(serialization.Encoding.PEM)[:-1]
        self._der = signed_csr.public_bytes(serialization.Encoding.DER)

        # extract public key for viewing
        if self._pvtkey_fmt == 'pkcs1':
            pub_fmt = serialization.PublicFormat.PKCS1
        else:
            pub_fmt = serialization.PublicFormat.SubjectPublicKeyInfo
        self._public_key = signed_csr.public_key().public_bytes(CSR.ENCODINGS['pem'], format=pub_fmt)[:-1]
        return
