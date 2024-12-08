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

    @pytest.mark.parametrize("cn,o,ou,l,st,email,c", [
        ('foo.com', 'acme', 'marketing', 'springfield', 'OH', 'jack@foo.com', 'US', )
    ])
    def test_fields(self, cn, o, ou, l, st, email, c):
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
        assert csr.is_signed == False

    @pytest.mark.parametrize("cn,sans,num_sans", [
        ('foo.com', ['bar.com', 'baz.com', 'bar.com', 'test.com'], 3,)
    ])
    def test_dns_names(self, cn, sans, num_sans):
        csr = CSR(my_rsa_key(), cn)
        for san in sans:  # add one at a time
            csr.add_san(san)  # filters duplicates
        san_names = csr.get_san_names()
        assert len(san_names) == num_sans  # prove duplicate was removed
        for san in san_names:
            assert san in sans
        set_sans = ['x.com', 'y.com', 'z.com']
        csr.sans = set_sans
        assert csr.get_san_names() == set_sans

    def test_presigned_outputs(self):
        csr = CSR(my_rsa_key(), 'foo.com')
        assert csr.is_signed == False
        assert csr.pem is None
        assert csr.der is None
        assert csr.out is None

    @pytest.mark.parametrize("select_encoding", ['pem', 'der'])
    def test_postsigned_outputs(self, select_encoding):
        csr = CSR(my_rsa_key(), 'foo.com', out_encoding=select_encoding)
        csr.finalize()
        assert select_encoding == csr.selected_encoding
        assert isinstance(csr.out, bytes)
        if select_encoding == 'pem':
            assert isinstance(csr.pem, bytes)
            assert b'-----BEGIN CERTIFICATE REQUEST-----' in csr.pem
            assert csr.out == csr.pem
        if select_encoding == 'der':
            assert isinstance(csr.der, bytes)
            assert b'foo.com' in csr.der
            assert csr.out == csr.der
