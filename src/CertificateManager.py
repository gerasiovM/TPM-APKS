import logging

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
import requests


class CertificateManager:
    def __init__(self, certificate, mode="DER"):
        if mode == "DER":
            self.certificate = x509.load_der_x509_certificate(certificate, default_backend())
        else:
            self.certificate = x509.load_pem_x509_certificate(certificate, default_backend())

    @staticmethod
    def get_issuer_certificate(cert):
        """Retrieve the issuer certificate from AIA if available."""
        try:
            aia = cert.extensions.get_extension_for_oid(x509.OID_AUTHORITY_INFORMATION_ACCESS)
            for access in aia.value:
                if access.access_method.dotted_string == "1.3.6.1.5.5.7.48.2":  # CA Issuers
                    issuer_url = access.access_location.value
                    return x509.load_der_x509_certificate(requests.get(issuer_url).content, default_backend())
        except x509.ExtensionNotFound:
            logging.warning("No AIA extension available. Check whether the discard certificate is the root one")
            return None

    @staticmethod
    def load_certificates_from_pem(file_path):
        certs = []
        with open(file_path, "rb") as f:
            pem_data = f.read()
            while pem_data:
                try:
                    cert, pem_data = x509.load_pem_x509_certificate(pem_data), b""
                    certs.append(cert)
                except ValueError:
                    break  # Stop if no more valid certificates
        return certs

    @staticmethod
    def check_certificate_root(cert_to_check: x509.Certificate, valid_cert_list: list[x509.Certificate]):
        cert_der = cert_to_check.public_bytes(encoding=serialization.Encoding.DER)
        return any(cert_der == ca_cert.public_bytes(encoding=serialization.Encoding.DER) for ca_cert in valid_cert_list)

    def check_certificate(self, cert=None):
        if not cert:
            cert = self.certificate
        if cert.issuer != cert.subject:
            issuer_certificate = self.get_issuer_certificate(cert)
            if not issuer_certificate:
                return False
            result = self.check_certificate(issuer_certificate)
            if not result:
                return False
            try:
                issuer_certificate.public_key().verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    cert.signature_hash_algorithm
                )
                return True
            except InvalidSignature:
                return False
        else:
            result = self.check_certificate_root(cert, self.load_certificates_from_pem(file_path="resources/certs/ca-certificates.crt"))
            return result

    def check_key(self, der_key):
        return der_key == self.certificate.public_key().public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)
