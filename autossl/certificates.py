from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat import backends
from autossl.keygen import RSAPrivateKey


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
            self, certificate_chain: str, key: str | RSAPrivateKey
    ):
        """Requires a private key and a certificate chain
        A certificate will not be considered deployable unless it has the following components:
        - A private key
        - A full certificate chain"""
        # TODO set the validated cert object to use for building out properties
        # TODO set the validated key object for building out cert properties
        pass

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
        # TODO check that 3 parts exist
        # TODO check that each part has valid PEM header and footer
        # TODO convert to binary
        # TODO set a cryptography certificate
        pass

    @classmethod
    def _process_private_key(cls, rsa_private_key: str):
        # TODO has valid PEM header and footer, either pkcs1 or pkcs8
        # TODO convert to binary
        # TODO set a cryptography RSAPvtKey
        pass

