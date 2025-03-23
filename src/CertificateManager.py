import logging

from OpenSSL import crypto
import requests
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding


class CertificateManager:
    TRUSTED_CERTIFICATES_PATH = "../resources/certs/ca-certificates.crt"
    def __init__(self, certificate, mode="DER"):
        if mode == "DER":
            self.certificate = crypto.load_certificate(crypto.FILETYPE_ASN1, certificate)
        else:
            self.certificate = crypto.load_certificate(crypto.FILETYPE_PEM, certificate)

    @staticmethod
    def get_certificate_extension(certificate: crypto.x509, extension_name: bytes):
        for i in range(certificate.get_extension_count()):
            extension = certificate.get_extension(i)
            if extension.get_short_name() == extension_name:
                return extension
        return None

    @staticmethod
    def get_issuer_certificate(certificate):
        """Retrieve the issuer certificate from AIA if available."""
        aia = CertificateManager.get_certificate_extension(certificate, b'authorityInfoAccess')
        if aia:
            for line in str(aia).split(','):
                if 'URI' in line:
                    issuer_url = line.split('URI:')[1].strip()
                    response = requests.get(issuer_url)
                    return crypto.load_certificate(crypto.FILETYPE_ASN1, response.content)
        else:
            logging.warning("No AIA extension available. Check whether the discarded certificate is the root one")
            return None

    @staticmethod
    def load_certificates_from_pem(file_path):
        certs = []
        with open(file_path, "rb") as f:
            pem_data = f.read()
        for cert_data in pem_data.split(b'-----END CERTIFICATE-----'):
            if cert_data:
                cert_data = cert_data + b'-----END CERTIFICATE-----'
                try:
                    cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_data)
                    certs.append(cert)
                except Exception as e:
                    logging.exception("Couldn't load certificate from file: {}".format(e))
        return certs

    @staticmethod
    def check_certificate_root(cert_to_check: crypto.x509, valid_cert_list: list[crypto.x509]):
        cert_der = crypto.dump_certificate(crypto.FILETYPE_ASN1, cert_to_check)
        return any(cert_der == crypto.dump_certificate(crypto.FILETYPE_ASN1, ca_cert) for ca_cert in valid_cert_list)

    @staticmethod
    def extract_certificate_signature(certificate) -> bytes:
        der_certificate = crypto.dump_certificate(crypto.FILETYPE_ASN1, certificate)
        signature_index = der_certificate.rfind(b'\x03') + 3
        signature = der_certificate[signature_index:]
        return signature

    @staticmethod
    def extract_tbs_certificate(certificate) -> bytes:
        der_certificate = crypto.dump_certificate(crypto.FILETYPE_ASN1, certificate)
        signature_algorithm_index = der_certificate.rfind(b'0\x0d')
        tbs_certificate = der_certificate[:signature_algorithm_index]
        return tbs_certificate



    @staticmethod
    def parse_signature_hash_algorithm(certificate) -> hashes.HashAlgorithm | None:
        signature_algorithm_bytes = certificate.get_signature_algorithm()
        if "sha256" in signature_algorithm_bytes.decode().lower():
            return hashes.SHA256()
        if "sha384" in signature_algorithm_bytes.decode().lower():
            return hashes.SHA384()
        if "sha512" in signature_algorithm_bytes.decode().lower():
            return hashes.SHA512()
        return None

    @staticmethod
    def parse_signature_algorithm(certificate) -> str | None:
        signature_algorithm_bytes = certificate.get_signature_algorithm()
        if "rsa" in signature_algorithm_bytes.decode().lower():
            return "rsa"
        if "ecdsa" in signature_algorithm_bytes.decode().lower():
            return "ecdsa"
        return None

    def check_certificate(self, cert=None) -> bool:
        if not cert:
            cert = self.certificate
        if cert.get_issuer() != cert.get_subject():
            issuer_certificate = self.get_issuer_certificate(cert)
            if not issuer_certificate:
                return False
            result = self.check_certificate(issuer_certificate)
            if not result:
                return False
            try:
                if self.parse_signature_algorithm(cert) == "rsa":
                    issuer_certificate.get_pubkey().to_cryptography_key().verify(
                        self.extract_certificate_signature(cert),
                        self.extract_tbs_certificate(cert),
                        padding.PKCS1v15(),
                        self.parse_signature_hash_algorithm(cert),
                    )
                if self.parse_signature_algorithm(cert) == "ecdsa":
                    issuer_certificate.get_pubkey().to_cryptography_key().verify(
                        self.extract_certificate_signature(cert),
                        self.extract_tbs_certificate(cert),
                        ec.ECDSA(self.parse_signature_hash_algorithm(cert))
                    )
                return True
            except InvalidSignature:
                return False
        else:
            result = self.check_certificate_root(cert, self.load_certificates_from_pem(self.TRUSTED_CERTIFICATES_PATH))
            return result

    def check_key(self, der_key):
        return der_key == self.certificate.get_pubkey().to_cryptography_key().public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)
