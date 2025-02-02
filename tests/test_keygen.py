import pytest
from sslauto.keygen import RSAPrivateKey as my_rsa_key
from sslauto.keygen import CSR
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives import serialization
import pprint

def pvtkey_to(key: RSAPrivateKey, to: str | bytes):
    d: bytes = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()
    )[:-1]
    if isinstance(to, bytes): return d
    return d.decode(encoding='utf-8')


class TestPrivateKey:

    @pytest.mark.parametrize("klen,encoding", [
        (2048, 'pkcs1', ), (3072, 'pkcs1', ), (4096, 'pkcs1', ),
        (2048, 'pkcs8',), (3072, 'pkcs8', ), (4096, 'pkcs8', )
    ])
    def test_properties(self, klen, encoding):
        key = my_rsa_key(exponent=65537, key_length=klen, fmt=encoding)
        pprint.pprint(key)
        assert key.key_len == klen
        assert isinstance(key._native_key_object, RSAPrivateKey)
        assert key._selected_encoding == 'pem'
        assert key.selected_format == encoding
        assert hasattr(key, 'pkcs1') and hasattr(key, 'pkcs8')

    def test_generated(self):
        key = my_rsa_key(pem=None)
        pprint.pprint(key)
        assert key.key_len == 2048

    def test_loaded(self, pvtkey):
        pem = pvtkey_to(pvtkey, str)
        assert isinstance(pem, str)
        key = my_rsa_key(pem=pem)
        pprint.pprint(key)
        assert key.key_len == 2048

    def test_serializations(self):
        key = my_rsa_key()
        assert b'-----BEGIN RSA PRIVATE KEY-----' in key.pkcs1
        assert b'-----BEGIN PRIVATE KEY-----' in key.pkcs8


class TestCSR:

    @pytest.mark.parametrize('use_str_key', [False, True])
    def test_generated(self, use_str_key, pvtkey):
        pem_str_key = pvtkey_to(pvtkey, str)
        autosslkey = my_rsa_key() if not use_str_key else pem_str_key
        csr = CSR(autosslkey, 'foo.com')
        csr.finalize()
        assert csr.is_signed == True
        assert csr.common_name == 'foo.com'
        assert b'foo.com' in csr.der
        assert b'-----BEGIN CERTIFICATE REQUEST-----' in csr.pem

    @pytest.mark.skip(reason="Not required")
    def test_loaded(self):
        pass

    @pytest.mark.parametrize("encoding", ['der', 'pem'])
    def test_available_encodings(self, encoding):
        csr = CSR(my_rsa_key(), 'foo.com')
        csr.finalize()
        assert hasattr(csr, 'der') and hasattr(csr, 'pem')

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
        csr.sans = ['bar.com', 'baz.com']
        assert csr.organization == o
        assert csr.organizational_unit == ou
        assert csr.locality == l
        assert csr.state == st
        assert csr.email == email
        assert csr.country == c
        assert csr.is_signed == False
        csr.finalize()
        assert csr.is_signed == True

        # demonstrate fields are closed for modification after signing
        for field in [
            'common_name', 'organization', 'organizational_unit', 'locality', 'state', 'email', 'country', 'sans'
        ]:
            setattr(csr, field, 'diddly squat')
            assert getattr(csr, field) != 'diddly squat'

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
        assert csr.public_key is None

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
        if csr._pvtkey_fmt == 'pkcs1':
            assert b'-----BEGIN RSA PUBLIC KEY-----' in csr.public_key
        if csr._pvtkey_fmt == 'pkcs8':
            assert b'-----BEGIN PUBLIC KEY-----' in csr.public_key

    @pytest.mark.parametrize("fmt,encoding", [
        ('pkcs1', 'pem', ),
        ('pkcs1', 'der', ),
        ('pkcs8', 'pem', ),
        ('pkcs8', 'der', )
    ])
    def test_get_public_key(self, fmt, encoding):
        csr = CSR(my_rsa_key(fmt=fmt), 'foo.com', out_encoding=encoding)
        csr.finalize()
        public_key = csr.get_public_key()
        print(public_key)

        if encoding == 'der':
            assert isinstance(public_key, bytes)
            assert b'PUBLIC KEY' not in public_key
        if encoding == 'pem':
            assert b'PUBLIC KEY' in public_key

