import pytest
from autossl.keygen import RSAPrivateKey as my_rsa_key
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey


class TestPrivateKey:

    @pytest.mark.parametrize("exponent,klen", [
        (65537, 2048, ), (65537, 3072, ), (65537, 4096, )
    ])
    def test_rsaprivatekey__init__(self, exponent, klen):
        key = my_rsa_key(exponent=exponent, key_length=klen)
        assert key.pub_exponent == exponent
        assert key.key_len == klen
        assert isinstance(key._native_key_object, RSAPrivateKey)
        assert key._selected_encoding == 'pem'

    @pytest.mark.parametrize("fmt,expected", [
        ('pkcs1', b'-----BEGIN RSA PRIVATE KEY-----', ), ('pkcs8', b'-----BEGIN PRIVATE KEY-----', ),
    ])
    def test_rsaprivatekey_formats(self, fmt, expected):
        key = my_rsa_key(fmt=fmt)
        actualkeystr = getattr(key, fmt)
        assert expected in actualkeystr
        assert expected.decode(encoding='utf-8') in str(actualkeystr)
