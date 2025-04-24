from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import Certificate, NameOID


class CertificateValidator:
    def __init__(self, ca_cert):
        """Initializes the CertificateValidator with a CA certificate."""
        self.ca_cert = ca_cert

    def validate_certificate(self, certificate: Certificate, except_iden: str) -> bool:
        """Validates the certificate against the CA certificate."""
        if (
            self.verify_signature(certificate)
            and self.verify_not_after(certificate)
            and self.verify_not_before(certificate)
            and self.verify_identity(certificate, except_iden)
        ):
            return True
        else:
            return False

    def verify_signature(self, certificate: Certificate) -> bool:
        issuer = certificate.issuer
        if issuer == self.ca_cert.subject:
            try:
                # Use the public key of the CA to verify the signature on the certificate
                self.ca_cert.public_key().verify(
                    certificate.signature,
                    certificate.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    certificate.signature_hash_algorithm,
                )
                return True
            except Exception as e:
                print(f"Signature verification failed: {e}")
                return False
        else:
            print("Certificate issuer does not match CA certificate subject.")
            return False

    def verify_not_after(self, certificate: Certificate) -> bool:
        now = datetime.now().astimezone(timezone.utc)

        if certificate.not_valid_after_utc < now:
            print("Certificate has expired.")
            return False
        return True

    def verify_not_before(self, certificate: Certificate) -> bool:
        now = datetime.now().astimezone(timezone.utc)

        if certificate.not_valid_before_utc > now:
            print("Certificate is not yet valid.")
            return False
        return True

    def verify_identity(self, certificate: Certificate, except_iden: str) -> bool:
        if (
            certificate.subject.get_attributes_for_oid(NameOID.PSEUDONYM)[0].value
            != except_iden
        ):
            print("Certificate identity does not match.")
            return False
        return True
