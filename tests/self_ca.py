from cryptography.x509 import CertificateBuilder
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
import datetime


class SelfSignedTestCA(object):
    """This represents an intermediate CA, which can sign and issue Digital Certificates as a leaf or for another intermediate CA. This is NOT a root CA."""

    def __init__(self, cn: str):
        self.cn = cn
        self.rsakey = self.generate_rsa_key()
        

    def generate_rsa_key(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        return key 


class SelfSignedTestRootCA(object):
    """This represents a root CA. It is the only certificate in the chain of trust that is self signed. It must keep it's private key ready for signing. It does NOT issue leaf certificates - it is only for delegation."""

    def __init__(self):
        self.cn = 'ROOT'
        # keep the key around to sign intermediate certs
        self.pvtkey = self.generate_root_key()
        self._cert = CertificateBuilder()  # see cert property for finalized cert
        self.is_signed = False

    def generate_root_key(self):
        return ec.generate_private_key(ec.SECP256R1())

    def build_certificate(self):
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, 'US'),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, 'NC'),
            x509.NameAttribute(NameOID.LOCALITY_NAME, 'Raleigh'),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'ROOT CA Corp'),
            x509.NameAttribute(NameOID.COMMON_NAME, 'ROOT CA'),
        ])

        self._cert = self._cert.subject_name(subject)
        self._cert = self._cert.issuer_name(issuer)
        self._cert = self._cert.public_key(self.pvtkey.public_key())
        self._cert = self._cert.serial_number(x509.random_serial_number())
        self._cert = self._cert.not_valid_before(
            datetime.datetime.now(datetime.timezone.utc)
        )
        self._cert = self._cert.not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
        )
        self._cert = self._cert.add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True
        )
        self._cert = self._cert.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
        self._cert = self._cert.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(
                self.pvtkey.public_key()
            ),
            critical=False
        )

    def sign(self):
        self._cert = self._cert.sign(self.pvtkey, hashes.SHA256())
        self.is_signed = True

    def generate_certificate(self):
        self.build_certificate()
        self.sign()
        return self.cert

    @property
    def cert(self):
        if not self.is_signed:
            raise ValueError("The certificate cannot be returned because it is not signed yet")
        return self._cert

    @property
    def pem(self):
        return self._cert.public_bytes(serialization.Encoding.PEM)[:-1]


def get_test_trust_chain():
    pass

if __name__ == '__main__':
    print("creating root CA...")
    ca = SelfSignedTestRootCA()
    print(ca.cn)
    ca.generate_certificate()
    print(ca.pem)
    print(ca.cert)
