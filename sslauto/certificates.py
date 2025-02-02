from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives import serialization
from sslauto.keygen import RSAPrivateKey
from cryptography.x509 import NameOID, load_pem_x509_certificate, Certificate
import re


class DeployableCertificate(object):
    """A certificate object used to deploy to different platforms that each want different serializations and formats,
    Base Certificate Components:
    - domain cert in bytes
    - ica cert in bytes
    - root cert in bytes
    - private key in bytes

    Certificates are expressable in the following encodings:
    - PEM (text)
    - DER (binary)
    - PFX/PKCS12 (binary)

    Certificates are formatted for popular cloud environments:
    - AWS
    - Azure
    """

    def __init__(self, certificate_chain: str, key: str | RSAPrivateKey):
        """Requires a private key and a certificate chain
        A certificate will not be considered deployable unless it has the following components:
        - A private key
        - A full certificate chain"""
        d, i, r = self._process_certificate_chain(certificate_chain)
        self._domain_cert: Certificate = d
        self._ica_cert: Certificate = i
        self._root_cert: Certificate = r
        self._cn = self._domain_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        self._rsa_key: RSAPrivateKey = self._process_private_key(key)
        self._pfxpkcs12 = self._pfx_pkcs12()


    def __repr__(self):
        domain_cn = self._cn
        serial_no = self._domain_cert.serial_number
        return f"<DeployableCertificate cn:{domain_cn} serial:{serial_no}>"

    @classmethod
    def _process_certificate_chain(cls, certificate_chain: str):
        fullchain_pem_pattern = re.compile(r"^(-----BEGIN CERTIFICATE-----\n[\S\s]+\n-----END CERTIFICATE-----)\n"
                                           r"(-----BEGIN CERTIFICATE-----\n[\S\s]+\n-----END CERTIFICATE-----)\n"
                                           r"(-----BEGIN CERTIFICATE-----\n[\S\s]+\n-----END CERTIFICATE-----)$")
        match = fullchain_pem_pattern.match(certificate_chain)
        if match is None:
            raise ValueError("The certificate passed in is not valid. "
                             "Ensure it is PEM encoded and has no leading or trailing white space.")
        parts = match.groups()
        if len(parts) != 3:
            raise ValueError(f"Expected 3 parts to the certificate chain. Received {len(parts)}")

        domain, ica, root = parts
        try:
            domain_certificate = load_pem_x509_certificate(domain.encode(encoding='utf-8'), backend=default_backend())
            ica_certificate = load_pem_x509_certificate(ica.encode(encoding='utf-8'), backend=default_backend())
            root_certificate = load_pem_x509_certificate(root.encode(encoding='utf-8'), backend=default_backend())
        except ValueError as ve:
            print("An error occurred while processing the deployable certificate chain.")
            raise ve

        return (domain_certificate, ica_certificate, root_certificate, )

    @classmethod
    def _process_private_key(cls, rsa_private_key: str | RSAPrivateKey):
        if isinstance(rsa_private_key, RSAPrivateKey):
            return rsa_private_key
        # if str
        pkcs1_pattern = re.compile(r"^-----BEGIN RSA PRIVATE KEY-----\n[\S\s]+\n-----END RSA PRIVATE KEY-----$")
        pkcs8_pattern = re.compile(r"^-----BEGIN PRIVATE KEY-----\n[\S\s]+\n-----END PRIVATE KEY-----$")

        if not pkcs8_pattern.match(rsa_private_key) and not pkcs1_pattern.match(rsa_private_key):
            raise ValueError("Invalid private key when initializing a Deployable Certificate. "
                             "Must be pkcs8 or pkcs1 formatted and have no leading or trailing white space.")

        return RSAPrivateKey(rsa_private_key)

    @property
    def domain_pem(self):
        return self._domain_cert.public_bytes(serialization.Encoding.PEM)[:-1]

    @domain_pem.setter
    def domain_pem(self, _):
        print("property is read-only")
        return

    @property
    def domain_der(self):
        return self._domain_cert.public_bytes(serialization.Encoding.DER)

    @domain_der.setter
    def domain_der(self, _):
        print("property is read-only")
        return

    @property
    def ica_pem(self):
        return self._ica_cert.public_bytes(serialization.Encoding.PEM)[:-1]

    @ica_pem.setter
    def ica_pem(self, _):
        print("property is read-only")
        return

    @property
    def ica_der(self):
        return self._ica_cert.public_bytes(serialization.Encoding.DER)

    @ica_der.setter
    def ica_der(self, _):
        print("property is read-only")
        return

    @property
    def root_pem(self):
        return self._root_cert.public_bytes(serialization.Encoding.PEM)[:-1]

    @root_pem.setter
    def root_pem(self, _):
        print("property is read-only")
        return

    @property
    def root_der(self):
        return self._root_cert.public_bytes(serialization.Encoding.DER)

    @root_der.setter
    def root_der(self, _):
        print("property is read-only")
        return

    @property
    def pem(self):
        d = self.domain_pem.decode(encoding='utf-8')
        i = self.ica_pem.decode(encoding='utf-8')
        r = self.root_pem.decode(encoding='utf-8')
        pem_cert = "{domain}\n{ica}\n{root}".format(domain=d, ica=i, root=r)
        return pem_cert.encode(encoding='utf-8')

    @pem.setter
    def pem(self, _):
        print("property is read-only")
        return

    @property
    def der(self):
        return self.domain_der + self.ica_der + self.root_der

    @der.setter
    def der(self, _):
        print("property is read-only")
        return

    @property
    def key_pkcs1(self):
        return self._rsa_key.pkcs1

    @key_pkcs1.setter
    def key_pkcs1(self, _):
        print("property is read-only")
        return

    @property
    def key_pkcs8(self):
        return self._rsa_key.pkcs8

    @key_pkcs8.setter
    def key_pkcs8(self, _):
        print("property is read-only")
        return

    def _pfx_pkcs12(self):
        encryption_algo = serialization.NoEncryption()
        return pkcs12.serialize_key_and_certificates(
            b'',
            self._rsa_key._native_key_object,
            self._domain_cert,
            cas=[self._ica_cert, self._root_cert],
            encryption_algorithm=encryption_algo
        )

    @property
    def pfx(self):
        return self._pfxpkcs12

    @pfx.setter
    def pfx(self, _):
        print("property is read-only")
        return

    @property
    def pkcs12(self):
        return self._pfxpkcs12

    @pkcs12.setter
    def pkcs12(self, _):
        print("property is read-only")

    @property
    def azure_pem(self):
        return self.pem + b'\n' + self.key_pkcs8

    @azure_pem.setter
    def azure_pem(self, _):
        print("property is read-only")
