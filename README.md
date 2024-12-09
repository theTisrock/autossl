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


Design Philosophy
- Components are useful independently or within a custom workflow.
- Components are flexible between different PKCS standards and encodings.


Functionality
- Keygen: Private Keys, CSRs
- Certificate Acquisition: CA interfacing and Certificate Objects


Install
```commandline
pip install autossl
```

## Keygen
Generate a private key and CSR
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

csr.finalize()  # assemble and sign your CSR
# NOTE: now that the csr is signed, you may not edit the fields
print(repr(csr))  # inspect your csr after signing; you'll notice it has changed

csr.out  # the CSR expressed in the selected encoding from when you set 'out_encoding'
csr.pem  # ...though you can still access each type explicitly
csr.der

# GET THE PUBLIC KEY
csr.get_public_key()  # public key format will match that of the private key
```

## Certificate Acquisition