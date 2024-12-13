

class CACertificatesInterface(object):
    """A common interface for any Certificate Authority that describes the generic process for
     CSR submission, Order Status checking and acquiring a digital certificate."""

    def submit_certificate_request(self, csr):
        """Submit the CSR for signing with the CA.
        Return the id that the CA has assigned to the cert or order"""
        raise NotImplemented("submit_certificate_request is not implemented.")

    def certificate_is_issued(self, id_):
        """Check the status of the certificate request using the id provided by the CA API.
        Return True if issued, False otherwise"""
        raise NotImplemented("certificate_is_issued is not implemented.")

    def fetch_certificate(self, id_):
        """fetch the certificate using the id provided by the CA API
        Return the full chain of the certificate divided up into a tuple, like (root, ca, domain, )"""
        raise NotImplemented("fetch_certificate is not implemented.")
