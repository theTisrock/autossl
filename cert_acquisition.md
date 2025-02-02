# Cryptographic Certificate Acquisition

### Keygen > [Cert Acquisition] > Distribution > Scan & Monitor

Certificate Authorities (<b>CA</b>) have the same generic process for obtaining SSL certificates: generate an asymmetric key pair, 
construct and sign a Certificate Signing Request (<b>CSR</b>) to house the public key, submit the CSR to the Certificate Authority, 
have the Ceritificate Authority verify your CSR details and generate a signed Certificate containing your public key,
and hand the final Certificate back to you.

###### problem(s)

1. Each Certificate Authority has it's own API for Certificate Acquisition. 
2. Each CA has it's own process to deal with CA/B Forum requirements. eg, omitting or requiring CSR fields.
3. Team members are required to know their way around CA processes, distracting them from their other objectives.

###### solution(s)

* Provide a common interface to make certificate acquisition generic and encapsulate individual CA processes.

###### benefit(s)

* Automate your certificate deployments and renewals
* CA's are a mere implementation detail.
* Remove the burden from your team to learn CA specifics.

###### Functional Features

1. DigiCert RestAPI client that submits CSRs, checks issuance status and downloads the full certificate chain.
2. Certificate Formatting & Serialization objects that make it easy to deploy by transforming the certificate chain into the desired PKCS formats and encodings.


###### Properties (Non-Functional requirements)

* Certificates pivot between binary formats and text formats. Binary formats: DER, CER; Text: PEM
* Certificates are made available in the following archive formats: PKCS12/PFX/P12 (different names, same format)
* CSRs are accepted as text or as objects from this library.

##  <u>EXAMPLES</u>

#### get a certificate from the CA

```python
from sslauto.ca_api import DigicertCertificates
from sslauto.keygen import CSR, RSAPrivateKey
import time

org_id = 123
ca = DigicertCertificates(org_id, api_key='<api key>')
```
##### use the autossl.keygen.CSR object ...
```python
# use the CSR from this library
key = RSAPrivateKey()
csr = CSR(key, 'foo.com')
csr.add_san('www.foo.com')
csr.country = 'US'
csr.finalize()

# for more info on how to build a CSR, see keygen.md
```

#### ... or bring your own CSR
```python
# remember to keep your private key handy
with open('csr_file.pem', 'r') as file: 
    csr = file.read()
```

#### fetch the certificate once it has been issued by the Certificate Authority
```python
order_id = ca.submit_certificate_request(csr)
while not ca.certificate_is_issued(order_id):
    # potentially infinite loop just for example
    seconds = 5
    time.sleep(seconds)

certificate_chain = ca.fetch_certificate(order_id)
domain, ica, root = certificate_chain  # tuple components are returned as bytes
# now you should have your private key and all your certificate chain components that you'll need to deploy
# see keygen.md for private object info. pkcs1 and pkcs8 are available as properties
```

## Certificate Objects

## CA Clients

###### <u>DigiCert</u>
```bash
export DIGICERT_ORGID=<your org id>
export DIGICERT_APIKEY=<your api key>
```

```python
from sslauto.ca_api import DigicertCertificates

digicert = DigicertCertificates()

# product settings
# require - only order duplicates, new - only order new certificate, prefer - order duplicate, if not found order new
digicert.set_duplicate_policy('new')
digicert.set_product_name('ssl_basic')  # ssl_basic, ssl_plus
digicert.set_days_valid(397)  # industry max is 397

# secondary api calls - used to support the main api calls
orders = digicert.list_orders()
order_id = 123456
order_info: dict = digicert.order_info(order_id)
duplicates_for_order = digicert.list_duplicates(order_id)

# main api calls
order_id = digicert.submit_certificate_request(csr)
if digicert.certificate_is_issued(order_id):
    certificate_chain = digicert.fetch_certificate(order_id)
domain_cert, ica_cert, root_cert = certificate_chain
```
