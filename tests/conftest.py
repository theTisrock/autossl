# fixtures for testing
import pytest
from .self_ca import get_test_trust_chain
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


@pytest.fixture(scope='function')
def csr_with_sans():
    test_csr = ("-----BEGIN CERTIFICATE REQUEST-----\n"  # cn: foo.com w/ multiple sans
                "MIICljCCAX4CAQAwEjEQMA4GA1UEAwwHZm9vLmNvbTCCASIwDQYJKoZIhvcNAQEB\n"
                "BQADggEPADCCAQoCggEBAK3tlcBM5fWfh0VPYhNjPhjLmrlbgFx6N69EvZdwyYX0\n"
                "LwZDaHm8voCILE706lTgXre70Of3D+licjPyn25FzfYZkPtbh2SsEknaWCxRBY0W\n"
                "e/IN5rZ0OuPhAHQIDWcmcOndajuqinjI4+mwrPYXq9WPX5kletvUA4iaVp2m+Y0k\n"
                "dzg2NUxVYPn0QAKQZpkTGtBcnUMBC6TEkFomkoaXL59qFPGMC7JnBDtZBU3goUWi\n"
                "OF8YQvAdNuGLLAhr9HGJys6Vr2podbKu+CjC2NA7kDbbTm+JiNevB/OMvhNKz3SM\n"
                "aqR385choyaZ6brNKU3frm5swSxIEOKY56QtvUdowmECAwEAAaA/MD0GCSqGSIb3\n"
                "DQEJDjEwMC4wLAYDVR0RBCUwI4ILd3d3LmZvby5jb22CB2Jhci5jb22CC3d3dy5i\n"
                "YXIuY29tMA0GCSqGSIb3DQEBCwUAA4IBAQCZmbVO3nu9wWCZDNGX3BQ7HPARSXd+\n"
                "Wf6NnjiS+97u6L7RGQLiMP+M6j7N3dG3M+Wgj9p45LdONFnftwILEzl1hAny7Yxz\n"
                "MytAnYiBhZOUhvHNWJH0GCDocqnGaXKfbE5ooHdkNsKwFion6A3JMb88l0y18MsW\n"
                "vJmw8uJUzemw/Qmu7IMguMOGFOgobELkTyYCPHOqFnCAvl+orGGTAfaDaIECz7W9\n"
                "7ga34sDjoWNzrfSgX+8GC/qby+hLgm+28joyto2I98qVqVGrMy3DM9bUttmr0tnY\n"
                "BtgchsOyBUr9k2KsfJwchzcOYNyAnoBB1+0l0a3g/HZiVFzXMWOykgFm\n"
                "-----END CERTIFICATE REQUEST-----")
    return test_csr

@pytest.fixture(scope='function')
def csr_without_sans():
    # foo.com
    test_csr = ("-----BEGIN CERTIFICATE REQUEST-----\n"
                "MIICczCCAVsCAQAwEjEQMA4GA1UEAwwHZm9vLmNvbTCCASIwDQYJKoZIhvcNAQEB\n"
                "BQADggEPADCCAQoCggEBALxzacrKKI36Um8Vy+y/wWv8TughvgyfwKRLBeSCxH/E\n"
                "NetqM09luEvqrgxyr3bQowYUrh7wRsZXh+qQbjNwxWAIp5fXqHvj8jsvUsyK/W4q\n"
                "6puauaZHEvPsAvr23PN65EOrQM09ClOSeoGyzo3Z4gaaz50mXt3fP4mKqpsJDxWR\n"
                "pIAyO4MqJCoU6wxv9n1Ob01Im9OW/+PdrLNS5qPiX5C8oKoJFWWbRYYuaKi8fkMw\n"
                "8YgLLMQkjQaYAqtc3nDpFN6d/B91sUZykPh6IUYn663gALFwx33zAU9AisT0cXKV\n"
                "66DVwTaR+HwzULtdvzZsNVKItraCDfwcm7vPyuNuxrECAwEAAaAcMBoGCSqGSIb3\n"
                "DQEJDjENMAswCQYDVR0RBAIwADANBgkqhkiG9w0BAQsFAAOCAQEAM94Y5pzFVdw/\n"
                "mGsGRYX/RJLr2HvWGlEWQ06CzXjKhqLSEWJsq+bGarY0IwQwtopTAZL1jHnz4eTT\n"
                "M/u1Rwj/TrL4+ywwfXVg7bQ9QaqSkmKtPs1P/juwnFLDXXAyXLm/qF1ioFm+rr/0\n"
                "1UhXk/xc+MT2lf3qaOnEvX3938pu0ytBBp56Do2alTQLgXxAd4h5GpuZ9z7a+xp+\n"
                "U0l/NFoDgcerGZACvDwwXpMNYJN1UFa/SwobIv4QT/4ttEzsFgXpXjJZQfzJGz3V\n"
                "DLmWVgrxJvC0cjq7jUQq1K5NRvvSVEkY/zscXkf0rypYj/yRrkdi/OgonHU2iPu4\n"
                "Hvof4Vk1WA==\n"
                "-----END CERTIFICATE REQUEST-----")
    return test_csr


@pytest.fixture(scope='function')
def certificate_chain():
    
    def _closure(cn: str, pvtkey):
        chain_key = get_test_trust_chain(cn, pvtkey)
        return chain_key

    return _closure

@pytest.fixture(scope='function')
def pvtkey():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

@pytest.fixture(scope='function')
def list_orders():
    # https://dev.digicert.com/en/certcentral-apis/services-api/orders/list-orders.html
    orders = {
        "orders": [
            {
                "id": 123456,
                "certificate": {
                    "id": 104,
                    "common_name": "example.com",
                    "dns_names": [
                        "example2.com",
                        "example3.com"
                    ],
                    "signature_hash": "sha256"
                },
                "status": "pending",
                "is_renewed": False,
                "date_created": "2018-10-16T17:29:56+00:00",
                "organization": {
                    "id": 112233,
                    "name": "Epigyne Unwieldiness llc"
                },
                "validity_years": 1,
                "disable_renewal_notifications": False,
                "container": {
                    "id": 14,
                    "name": "DigiCert Inc."
                },
                "product": {
                    "name_id": "ssl_plus",
                    "name": "Standard SSL",
                    "type": "ssl_certificate"
                },
                "has_duplicates": False,
                "product_name_id": "ssl_plus"
            },
            {
                "id": 123457,
                "certificate": {
                    "id": 105,
                    "common_name": "example.org",
                    "dns_names": [
                        "sub.example.org"
                    ],
                    "valid_till": "2020-04-30",
                    "days_remaining": 289,
                    "signature_hash": "sha256"
                },
                "status": "issued",
                "is_renewed": False,
                "date_created": "2019-04-30T18:02:50+00:00",
                "organization": [],
                "validity_years": 1,
                "container": {
                    "id": 14,
                    "name": "CertCentral"
                },
                "product": {
                    "name_id": "ssl_dv_geotrust",
                    "name": "GeoTrust Standard DV",
                    "type": "dv_ssl_certificate"
                },
                "has_duplicates": False,
                "product_name_id": "ssl_dv_geotrust"
            }
        ],
        "page": {
            "total": 31,
            "limit": 0,
            "offset": 0
        }
    }
    return orders
