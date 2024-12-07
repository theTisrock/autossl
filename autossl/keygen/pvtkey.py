from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


KEY_SIZES = { 2048, 3072, 4096 }
PUBLIC_EXPONENTS = { 65537 }
BACKENDS = { default_backend }
KEY_FORMATS = {'pkcs1', 'pkcs8'}


class RSAPrivateKey(object):

    KEY_SIZE = 2048
    PUBLIC_EXPONENT = 65537
    BACKEND = default_backend

    FORMATS = {'pkcs1': serialization.PrivateFormat.TraditionalOpenSSL,
               'pkcs8': serialization.PrivateFormat.PKCS8}

    ENCODINGS = {'pem': serialization.Encoding.PEM,
                 'der': serialization.Encoding.DER}

    def __init__(
            self, exponent: int = PUBLIC_EXPONENT, key_length: int = KEY_SIZE, backend = BACKEND, fmt: str = 'pkcs1'
    ):

        if not ((exponent in PUBLIC_EXPONENTS) and (key_length in KEY_SIZES) and (backend in BACKENDS) and fmt in KEY_FORMATS):
            raise ValueError(
                f"RSAPrivateKey configuration not accepted. "
                f"exponent:{exponent},key size:{key_length},fmt:{fmt}"
            )

        self._native_key_object = rsa.generate_private_key(
            public_exponent=exponent, key_size=key_length, backend=backend()
        )
        self.pub_exponent = exponent
        self.key_len = key_length
        self.backend_name = backend.__name__
        self._selected_format = fmt
        self._selected_encoding = 'pem'

    def __repr__(self):
        return f"<RSAPvtKey:{id(self)} exp:{self.pub_exponent},{self.key_len}-bits,{self._selected_format}>"

    def __str__(self):
        key: bytes = getattr(self, self._selected_format)
        return key.decode(encoding='utf-8')

    @property
    def pkcs1(self):
        key_bytes = self._native_key_object.private_bytes(
            self.ENCODINGS[self._selected_encoding],
            self.FORMATS['pkcs1'],
            serialization.NoEncryption()
        )
        return key_bytes[:-1]

    @pkcs1.setter
    def pkcs1(self, _):
        raise ValueError("The private key cannot be set using the pkcs1 property.")

    @property
    def pkcs8(self):
        key_bytes = self._native_key_object.private_bytes(
            self.ENCODINGS[self._selected_encoding],
            self.FORMATS['pkcs8'],
            serialization.NoEncryption()
        )
        return key_bytes[:-1]

    @pkcs8.setter
    def pkcs8(self, _):
        raise ValueError("The private key cannot be set using the pkcs8 property.")
