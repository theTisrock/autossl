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

# Guide
## Keygen

Generate your private-public key pair and a CSR

<u>Generate a private key or load your own</u>
```python
from autossl.keygen import RSAPrivateKey

key = RSAPrivateKey()  # library generated

text: str = None
with open('rsakey.pem', mode='r') as rsakeyfile:
    text = rsakeyfile.read()
    rsakeyfile.close()
    
key = RSAPrivateKey(pem=text)  # load your own into the library component

# serializations - two pem formats available as properties
key.pkcs1
key.pkcs8
```

<u>Generate a CSR</u>

A user supplied CSR may be supplied as PEM-encoded text when requesting a certificate with a certificate authority.
There is no apparent need to load a CSR component into a library object.

Below demonstrates a library generated CSR that allows for customization.
```python
from autossl.keygen import CSR

csr = CSR(key, 'foobar.com')
csr.organization = 'Acme Corp'
csr.organizational_unit = "marketing"
csr.country = 'US'
csr.add_san('www.foobar.com')  # add dns names 1 at a time
csr.sans = ['foo.com', 'www.bar.com']  # override the dns names

csr.finalize()  # Finalizing is required before submitting to the CA
# NO MORE MODIFICATIONS AFTER SIGNING

csr.get_public_key()
# NOTE: When sending the CSR to the Certificate Authority, you can use your own raw PEM formatted version and skip this

# serializations
csr.out  # out is set at instantiation and can be changed from its default like CSR(... , out_encoding='der')
csr.pem  # or you can select explicitly
csr.der
```

## Certificate Acquisition - CA Clients

...continuing from above...
```python
from autossl.ca_api import DigicertCertificates
import time

org_id = 123
ca_api_client = DigicertCertificates(org_id=org_id, api_key='<your api key>')

# Use the generated csr
order_id = ca_api_client.submit_certificate_request(csr)  # using the csr from above

text_csr: str = None
with open('csr.pem', mode='r') as csr:
    text_csr = csr.read()
    csr.close()
    
order_id = ca_api_client.submit_certificate_request(text_csr)  # user supplied csr

counter_limit = 10
counter = 0
while not ca_api_client.certificate_is_issued(order_id):  # check issuance status
    time.sleep(5)
    if counter > counter_limit: break
    counter += 1

d, i, r = ca_api_client.fetch_certificate(order_id)
domain: bytes = d
intermediate: bytes = i
root: bytes = r

# congrats! Now you have a newly issued certificate
```

Now you're at a point where you where you could begin automating the distribution of new or renewed SSL/TLS Certificates.

Depending on your enterprise environment, you may need to distribute that certificate to multiple platform APIs.
Each API has different requirements. 

Azure requires SSL/TLS certificates destined for Application Gateway to be in PFX format.
You can also use a PEM format with a catch... the private key must be appended to the bottom of the full certificate chain.

But AWS wants you to separate out the components for ACM like: [pkcs1 private key] + [ICA & Root cert chain] + [domain cert]

Other platforms have their own requirements. It's a lot of work to convert between formats and encodings.

Introducing SSL certificae Serialization!!!

## Deployable Certificates

A multi-serializable SSL/TLS Certificate object.
A deployable cert is one that has the full certificate chain of trust with it's associated private key. 

Continuing with the downloaded certificate in the code sample above...

```python
from autossl.certificates import DeployableCertificate


certificate_chain = f"{domain.decode()}\n{ica.decode()}\n{root.decode()}"
cert = DeployableCertificate(certificate_chain, key)  # load library generated key from example above

pem_key: str = None
with open('rsakey.pem', mode='r') as keyfile:
    pem_key = keyfile.read()
    keyfile.close()
cert = DeployableCertificate(certificate_chain, pem_key)  # load user supplied key

# certificate serializations - outputs all in bytes
cert.pem  # fullchain - 2 options
cert.der
cert.domain_pem  # individual components encodded as PEM or DER
cert.domain_der
cert.ica_pem
cert.ica_der
cert.root_pem
cert.root_der
cert.key_pkcs1  # 2 private key serializations, both PEM. AWS ACM wants pkcs1
cert.key_pkcs8  # azure likes pkcs8
cert.pfx  # bundled cert chain plus private key. Used for Azure Application Gateway.
cert.pkcs12  # alias for pfx
cert.azure_pem  # Azure full chain with pkcs8 key

# REMEMBER: use the bytes.decode() if you want these in string format for any PEM encoded components
```