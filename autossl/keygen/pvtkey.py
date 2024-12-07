from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


KEY_SIZES = { 2048, 3072, 4096 }
PUBLIC_EXPONENTS = { 65537 }
BACKENDS = { default_backend }


class RSAPrivateKey(object):

    KEY_SIZE = 2048
    PUBLIC_EXPONENT = 65537
    BACKEND = default_backend

    def __init__(self, exponent: int = PUBLIC_EXPONENT, key_length: int = KEY_SIZE, backend = BACKEND):

        if not ((exponent in PUBLIC_EXPONENTS) and (key_length in KEY_SIZES) and (backend in BACKENDS)):
            raise ValueError(
                f"RSAPrivateKey configuration not accepted. "
                f"exponent:{exponent},key_size:{key_length},backend:{backend.__name__}"
            )

        self._native_key_object = rsa.generate_private_key(
            public_exponent=exponent, key_size=key_length, backend=backend()
        )
        self.pub_exponent = exponent
        self.key_len = key_length
        self.backend_name = backend.__name__
        pass

    def __repr__(self):
        return f"<RSAPvtKey:{id(self)} exp:{self._pub_exponent},{self._key_len}-bits,{self._backend_name}>"

    def __str__(self):
        pass


    @property
    def pkcs1(self):
        return self._key

    @pkcs1.setter
    def pkcs1(self, _):
        raise ValueError("The private key cannot be set using the pkcs1 property.")

    @property
    def pkcs8(self):
        return self._key

    @pkcs8.setter
    def pkcs8(self, _):
        raise ValueError("The private key cannot be set using the pkcs8 property.")

    pass
