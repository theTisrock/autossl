import pytest
from autossl.keygen import RSAPrivateKey as my_rsa_key
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey


class TestPrivateKey:

    @pytest.mark.parametrize("exponent,klen", [
        (65537, 2048, ), (65537, 3072, ), (65537, 4096, )
    ])
    def test_rsa_private_key__init__(self, exponent, klen):
        key = my_rsa_key(exponent=exponent, key_length=klen)
        assert key.pub_exponent == exponent
        assert key.key_len == klen
        assert isinstance(key._native_key_object, RSAPrivateKey)
