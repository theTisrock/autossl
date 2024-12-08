import pytest
from autossl.keygen import RSAPrivateKey as my_rsa_key
from autossl.keygen import CSR
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
import pprint


class TestPrivateKey:

    @pytest.mark.parametrize("exponent,klen", [
        (65537, 2048, ), (65537, 3072, ), (65537, 4096, )
    ])
    def test__init__(self, exponent, klen):
        key = my_rsa_key(exponent=exponent, key_length=klen)
        pprint.pprint(key)
        assert key.pub_exponent == exponent
        assert key.key_len == klen
        assert isinstance(key._native_key_object, RSAPrivateKey)
        assert key._selected_encoding == 'pem'

    @pytest.mark.parametrize("fmt,expected", [
        ('pkcs1', b'-----BEGIN RSA PRIVATE KEY-----', ), ('pkcs8', b'-----BEGIN PRIVATE KEY-----', ),
    ])
    def test_formats(self, fmt, expected):
        key = my_rsa_key(fmt=fmt)
        actualkeystr = getattr(key, fmt)
        pprint.pprint(actualkeystr)
        assert chr(actualkeystr[-1]) not in ['\n', '\r']
        assert expected in actualkeystr
        assert expected.decode(encoding='utf-8') in str(actualkeystr)


class TestCSR:

    def test__init__(self):
        csr = CSR(my_rsa_key(), 'foo.com')
        assert csr.common_name == 'foo.com'
        try:  # not allowed to call fields before they are set
            print(csr)
            csr.email
            assert False
        except AttributeError:
            assert True

    @pytest.mark.parametrize("cn,o,ou,l,st,email,c", [
        ('foo.com', 'acme', 'marketing', 'springfield', 'OH', 'jack@foo.com', 'US', )
    ])
    def test_csr_fields(self, cn, o, ou, l, st, email, c):
        csr = CSR(my_rsa_key(), cn)
        csr.organization = o
        csr.organizational_unit = ou
        csr.locality = l
        csr.state = st
        csr.email = email
        csr.country = c

        assert csr.organization == o
        assert csr.organizational_unit == ou
        assert csr.locality == l
        assert csr.state == st
        assert csr.email == email
        assert csr.country == c
