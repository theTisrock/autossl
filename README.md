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

Generate a private key or use your own
```python
from autossl.keygen import RSAPrivateKey, CSR

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

Generate the CSR
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