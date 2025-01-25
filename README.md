# autossl
<b>Automate your SSL certificate workflows</b>

author: Chris Torok

## Features & Benefits:
- Automate the PKI keygen process: Private Keys, Certificate Signing Requests (CSR)s

<u>Why</u>?
1. Each platform API wants cryptographic components provided in different layout structures, different encodings, 
and different data types.
2. Each Certificate Authority has different processes for handling CSR requests for new certificates and requesting new 
"duplicate" certificates.
3. Prevent outages and reduced traffic by assessing your PKI footprint across cloud platforms and third-party services.


Design Philosophy (non-functional requirements)
- Cryptographic assets are useful independently as data or within a custom workflow as either data or proprietary objects.
- Cryptographic objects are flexible between different PKCS standards and encodings.


Functionality (functional requirements)
Keygen > Cert Acquisition > Platform Distribution (cloud | 3rd party) > Footprint Scans & Monitoring

- Keygen: Private Keys, CSRs
- Certificate Acquisition: CA interfacing and Certificate Objects


Install
```commandline
pip install autossl
```

## Keygen
Generate a private key and CSR.

This key pair are cryptographically binded to each other.
The CSR contains the public key. The public key is calculated from the private key.
```python
from autossl import keygen
# ---------------------- SIMPLE - PEM encoded, pkcs1 format, no SANs -------------------------
pvtkey = keygen.RSAPrivateKey()  # generate rsa key
csr = keygen.CSR(pvtkey, 'foo.com')  # initialize a csr
csr.finalize()  # sign the csr
csr.get_public_key()  # optional: get the public key


# ------------------------------ EXPANDED ----------------------------------------
# GENERATE A PRIVATE KEY
print("generating private key...")
pvtkey = keygen.RSAPrivateKey(fmt='pkcs8')  # default is pkcs1
pvtkey = keygen.RSAPrivateKey(key_length=4096)  # default is 2048; choices: 2048, 3072, 4096
pvtkey.pkcs1  # get different formats, all currently in PEM encoding
pvtkey.pkcs8
print(repr(pvtkey))

# GENERATE A CSR
print("generating csr...")
csr = keygen.CSR(pvtkey, 'foo.com', critical=True, out_encoding='der')  # defaults: critical=True, out_encoding='pem'
print(repr(csr))
print("adding metadata to csr")
# NOTE: out_encoding selects the main output encoding. (see below)
csr.country = 'US'  # build your CSR fields
csr.email = 'joe.smith@foo.com'
csr.state = 'CA'
csr.locality = 'San Jose'
csr.organization = 'ACME'
csr.organizational_unit = 'marketing'
csr.common_name = 'bar.com'  # changes from foo.com to bar.com, optional
csr.common_name = 'foo.com'
csr.sans = ['bar.com', 'baz.com', 'foobar.com']
csr.add_san('www.foo.com')
print(repr(csr))  # you can inspect your csr before signing it
print("signing csr...")
csr.finalize()  # assemble and sign your CSR
# NOTE: now that the csr is signed, you may not edit the fields
print(repr(csr))  # inspect your csr after signing; you'll notice it has changed

print("csr")
print(csr.out)  # the CSR expressed in the selected encoding from when you set 'out_encoding'
csr.pem  # ...though you can still access each type explicitly
csr.der

# GET THE PUBLIC KEY
print("getting public key...")
print(csr.get_public_key())  # public key format will match that of the private key
```

## Certificate Acquisition
Pull a new certificate from the Certificate Authority.
```python
from autossl.ca_api import DigicertCertificates


organization_id = 123
api_key='<my api key>'
digicert = DigicertCertificates(organization_id, api_key=api_key)

order_id = digicert.submit_certificate_request(csr)  # <- you can also use a raw PEM csr here

if digicert.certificate_is_issued(order_id):
    chain = digicert.fetch_certificate(order_id)
    domain: bytes = chain[0]
    intermediate: bytes = chain[1]
    root: bytes = chain[2]
else:
    print("Certificate not issued.")
```

## Certificate Serialization
Prepare the certificate for distribution to 1 or many platforms.

Remember that private key from above? Use it here.
```python
from autossl.certificates import DeployableCertificate


chain: str = f"{domain.decode()}\n{intermediate.decode()}\n{root.decode()}"
cert = DeployableCertificate(chain, pvtkey)

# now you can split the cert into different components, formats and encodings
# ALL OUTPUTS ARE IN BYTES. This is what most platforms want. Use str.decode() if you need a string.
cert.pem  # full chain pem and der encodings
cert.der
cert.domain_pem  # pem components, same for der: domain_der ... etc
cert.ica_pem
cert.root_pem
cert.pfx  # for azure application gateway. Same as pkcs12
cert.pkcs12
cert.azure_pem  # full chain pem with pkcs8 key at the bottom
cert.key_pkcs1  # You can access the private key from the cert in 2 pem formats
cert.key_pkcs8

```