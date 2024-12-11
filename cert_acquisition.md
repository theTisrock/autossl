# Cryptographic Certificate Acquisition
Certificate Rotation Automation chain:

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
## CA Clients

1. DigiCert
2. TODO: Let's Encrypt???

## Certificate Objects
