# configuration for testing
import pytest


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
    cert = """-----BEGIN CERTIFICATE-----
MIID+TCCAuGgAwIBAgIUcN3rnkvKiEPbxObg/q+MAvrJvlIwDQYJKoZIhvcNAQEL
BQAwgYsxCzAJBgNVBAYTAlVTMRcwFQYDVQQIDA5Ob3J0aCBDYXJvbGluYTESMBAG
A1UEBwwJQXNoZXZpbGxlMRIwEAYDVQQKDAlBQ01FIENvcnAxDTALBgNVBAsMBHBy
b2QxEDAOBgNVBAMMB2Zvby5jb20xGjAYBgkqhkiG9w0BCQEWC2ppbUBmb28uY29t
MB4XDTI0MTIyMDIwMjIwN1oXDTI1MTIyMDIwMjIwN1owgYsxCzAJBgNVBAYTAlVT
MRcwFQYDVQQIDA5Ob3J0aCBDYXJvbGluYTESMBAGA1UEBwwJQXNoZXZpbGxlMRIw
EAYDVQQKDAlBQ01FIENvcnAxDTALBgNVBAsMBHByb2QxEDAOBgNVBAMMB2Zvby5j
b20xGjAYBgkqhkiG9w0BCQEWC2ppbUBmb28uY29tMIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAvhmZCYL0vkkMl4xAYnFkacsXPxnA7gs4IsnRIvOjpiuc
kwVKOBFceHehW4wlXatMqtVV3Y1WKLy7wfZjR3zXPlCEPsduOj5LoMV1cXO2bSYq
9Nf5a85+6ydUSgO/5u4UwgXPJXd4ebJeuKb0TeUfLL36RuAJydsCHpYDBcj8pGd2
mfHoPCkiHDJvBFck097kH/4sxuvZ+U0a194fzL0xS36SWU18TKfuFJBqQHUY+Ujh
QCoKvUQPS8ubk9rfuML4T76BMrxTrOs5UDbL7JEgFTPXDGhm/sJ1rQ9RGox9dMhl
Trb7CybvhejvSIwHP/p79WbMajFJ8hXOw27U73A4uwIDAQABo1MwUTAdBgNVHQ4E
FgQUYoU17S3pEgQJfA0Xv9Xp7NvmsaQwHwYDVR0jBBgwFoAUYoU17S3pEgQJfA0X
v9Xp7NvmsaQwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAHjiq
/88BTnwFfnxtiuBxKbsfcw3uajvWxKicAHGwPtNNhzcxoT2iMN3QHf2fyAEsShvR
+Nf6WHY+iQ340qudfjMHN/sdkOBqNj/FfYD3jJa7MN+l3R8TyJAT8hCc68Q0GohJ
SaqbuWvEGj5K5vwb3/z5sFijzbv0SYfJsG/n2/oXj2KcQPKv+qUGniD141Mu9ftt
kDb9JHSscVQECCx6CTBNVevfeUihUQkBE57p5i3GwDN/9sh22Mg8N3cCV0U3r62t
PcX92elAKkBvgdLjXnMTqBAWCWrrLIfp3iQ3sjCt+VWD1MYTdN4UNeb7QSHuauhm
TD7tafbGjeswEy8vvA==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIEFzCCAv+gAwIBAgIQB/LzXIeod6967+lHmTUlvTANBgkqhkiG9w0BAQwFADBh
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBD
QTAeFw0yMTA0MTQwMDAwMDBaFw0zMTA0MTMyMzU5NTlaMFYxCzAJBgNVBAYTAlVT
MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxMDAuBgNVBAMTJ0RpZ2lDZXJ0IFRMUyBI
eWJyaWQgRUNDIFNIQTM4NCAyMDIwIENBMTB2MBAGByqGSM49AgEGBSuBBAAiA2IA
BMEbxppbmNmkKaDp1AS12+umsmxVwP/tmMZJLwYnUcu/cMEFesOxnYeJuq20ExfJ
qLSDyLiQ0cx0NTY8g3KwtdD3ImnI8YDEe0CPz2iHJlw5ifFNkU3aiYvkA8ND5b8v
c6OCAYIwggF+MBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFAq8CCkXjKU5
bXoOzjPHLrPt+8N6MB8GA1UdIwQYMBaAFAPeUDVW0Uy7ZvCj4hsbw5eyPdFVMA4G
A1UdDwEB/wQEAwIBhjAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwdgYI
KwYBBQUHAQEEajBoMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5j
b20wQAYIKwYBBQUHMAKGNGh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdp
Q2VydEdsb2JhbFJvb3RDQS5jcnQwQgYDVR0fBDswOTA3oDWgM4YxaHR0cDovL2Ny
bDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0R2xvYmFsUm9vdENBLmNybDA9BgNVHSAE
NjA0MAsGCWCGSAGG/WwCATAHBgVngQwBATAIBgZngQwBAgEwCAYGZ4EMAQICMAgG
BmeBDAECAzANBgkqhkiG9w0BAQwFAAOCAQEAR1mBf9QbH7Bx9phdGLqYR5iwfnYr
6v8ai6wms0KNMeZK6BnQ79oU59cUkqGS8qcuLa/7Hfb7U7CKP/zYFgrpsC62pQsY
kDUmotr2qLcy/JUjS8ZFucTP5Hzu5sn4kL1y45nDHQsFfGqXbbKrAjbYwrwsAZI/
BKOLdRHHuSm8EdCGupK8JvllyDfNJvaGEwwEqonleLHBTnm8dqMLUeTF0J5q/hos
Vq4GNiejcxwIfZMy0MJEGdqN9A57HSgDKwmKdsp33Id6rHtSJlWncg+d0ohP/rEh
xRqhqjn1VtvChMQ1H3Dau0bwhr9kAMQ+959GG50jBbl9s08PqUU643QwmA==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDrzCCApegAwIBAgIQCDvgVpBCRrGhdWrJWZHHSjANBgkqhkiG9w0BAQUFADBh
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBD
QTAeFw0wNjExMTAwMDAwMDBaFw0zMTExMTAwMDAwMDBaMGExCzAJBgNVBAYTAlVT
MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j
b20xIDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IENBMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4jvhEXLeqKTTo1eqUKKPC3eQyaKl7hLOllsB
CSDMAZOnTjC3U/dDxGkAV53ijSLdhwZAAIEJzs4bg7/fzTtxRuLWZscFs3YnFo97
nh6Vfe63SKMI2tavegw5BmV/Sl0fvBf4q77uKNd0f3p4mVmFaG5cIzJLv07A6Fpt
43C/dxC//AH2hdmoRBBYMql1GNXRor5H4idq9Joz+EkIYIvUX7Q6hL+hqkpMfT7P
T19sdl6gSzeRntwi5m3OFBqOasv+zbMUZBfHWymeMr/y7vrTC0LUq7dBMtoM1O/4
gdW7jVg/tRvoSSiicNoxBN33shbyTApOB6jtSj1etX+jkMOvJwIDAQABo2MwYTAO
BgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUA95QNVbR
TLtm8KPiGxvDl7I90VUwHwYDVR0jBBgwFoAUA95QNVbRTLtm8KPiGxvDl7I90VUw
DQYJKoZIhvcNAQEFBQADggEBAMucN6pIExIK+t1EnE9SsPTfrgT1eXkIoyQY/Esr
hMAtudXH/vTBH1jLuG2cenTnmCmrEbXjcKChzUyImZOMkXDiqw8cvpOp/2PV5Adg
06O/nVsJ8dWO41P0jmP6P6fbtGbfYmbW0W5BjfIttep3Sp+dWOIrWcBAI+0tKIJF
PnlUkiaY4IBIqDfv8NZ5YBberOgOzW6sRBc4L0na4UU+Krk2U886UAb3LujEV0ls
YSEY1QSteDwsOoBrp+uvFRTp2InBuThs4pFsiv9kuXclVzDAGySj4dzp30d8tbQk
CAUw7C29C79Fv1C5qfPrmAESrciIxpg0X40KPMbp1ZWVbd4=
-----END CERTIFICATE-----
"""
    return cert

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
