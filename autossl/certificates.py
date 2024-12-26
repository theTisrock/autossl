from idlelib.iomenu import encoding

from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat import backends
from autossl.keygen import RSAPrivateKey
from cryptography.x509 import NameOID, load_pem_x509_certificate
import re


# class DigitalCertificate:

    # @staticmethod
    # def load_pem_certificate(certificate: str):
    #


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

    def __init__(
            self, certificate_chain: str  #, key: str | RSAPrivateKey
    ):
        """Requires a private key and a certificate chain
        A certificate will not be considered deployable unless it has the following components:
        - A private key
        - A full certificate chain"""
        # TODO set the validated cert object to use for building out properties
        d, i, r = self._process_certificate_chain(certificate_chain)
        self._domain_cert = d
        self._ica_cert = i
        self._root_cert = r
        # TODO set the validated key object for building out cert properties


    def __repr__(self):
        # TODO repr the root by CN
        # TODO repr the ica by CN
        # TODO repr the domain by CN
        # TODO repr the key by length
        # TODO repr the hash algo
        # TODO repr sans by sans count
        # TODO repr serial number
        pass

    @classmethod
    def _process_certificate_chain(cls, certificate_chain: str):
        fullchain_pem_pattern = re.compile("^(-----BEGIN CERTIFICATE-----\n[\S\s]+\n-----END CERTIFICATE-----)\n"
                                           "(-----BEGIN CERTIFICATE-----\n[\S\s]+\n-----END CERTIFICATE-----)\n"
                                           "(-----BEGIN CERTIFICATE-----\n[\S\s]+\n-----END CERTIFICATE-----)$")
        match = fullchain_pem_pattern.match(certificate_chain)
        if match is None:
            raise ValueError("The certificate passed in is not valid. "
                             "Ensure it is PEM encoded and has no leading or trailing white space.")
        parts = match.groups()
        if len(parts) != 3:
            raise ValueError(f"Expected 3 parts to the certificate chain. Received {len(parts)}")

        domain, ica, root = parts
        try:
            domain_certificate = load_pem_x509_certificate(domain.encode(encoding='utf-8'))
            ica_certificate = load_pem_x509_certificate(ica.encode(encoding='utf-8'))
            root_certificate = load_pem_x509_certificate(root.encode(encoding='utf-8'))
        except ValueError as ve:
            print("An error occurred while processing the deployable certificate chain.")
            raise ve

        return (domain_certificate, ica_certificate, root_certificate, )

    @classmethod
    def _process_private_key(cls, rsa_private_key: str):
        # TODO has valid PEM header and footer, either pkcs1 or pkcs8
        # TODO convert to binary
        # TODO set a cryptography RSAPvtKey
        pass

