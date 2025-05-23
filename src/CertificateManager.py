import logging
from OpenSSL import crypto
import re
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
    def parse_length(data, idx) -> [int, int]:
        length = data[idx]
        if length & 0x80:  # Long form
            num_bytes = length & 0x7F
            length = int.from_bytes(data[idx + 1: idx + 1 + num_bytes], 'big')
            idx += num_bytes
        return length, idx + 1

    # Dumps certificate into ASN1(DER) format and parses out TBS (To Be Signed) and Signature parts of it
    @staticmethod
    def extract_tbs_and_signature(cert):
        cert_bytes = crypto.dump_certificate(crypto.FILETYPE_ASN1, cert)
        idx = 0

        # Check for SEQUENCE (0x30)
        if cert_bytes[idx] != 0x30:
            raise ValueError("Invalid certificate format")
        idx += 1

        # Parse the total length of the certificate
        cert_len, idx = CertificateManager.parse_length(cert_bytes, idx)

        # Extract the tbsCertificate (first element of the SEQUENCE)
        if cert_bytes[idx] != 0x30:  # tbsCertificate should start with SEQUENCE (0x30)
            raise ValueError("Invalid tbsCertificate format")
        tbs_start = idx
        tbs_len, idx = CertificateManager.parse_length(cert_bytes, idx + 1)
        tbs_end = idx + tbs_len
        tbs_certificate = cert_bytes[tbs_start:tbs_end]

        # Skip to the signature value (last element, BIT STRING)
        idx = tbs_end
        if cert_bytes[idx] != 0x30:  # Signature algorithm identifier, a SEQUENCE (0x30)
            raise ValueError("Invalid signature algorithm format")
        algo_len, idx = CertificateManager.parse_length(cert_bytes, idx + 1)
        idx += algo_len

        if cert_bytes[idx] != 0x03:  # BIT STRING tag (0x03)
            raise ValueError("Invalid signature format")
        sig_len, idx = CertificateManager.parse_length(cert_bytes, idx + 1)
        signature = cert_bytes[idx + 1:idx + sig_len]

        return tbs_certificate, signature

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
                tbs, sig = self.extract_tbs_and_signature(cert)
                if self.parse_signature_algorithm(cert) == "rsa":
                    issuer_certificate.get_pubkey().to_cryptography_key().verify(
                        sig,
                        tbs,
                        padding.PKCS1v15(),
                        self.parse_signature_hash_algorithm(cert),
                    )
                if self.parse_signature_algorithm(cert) == "ecdsa":
                    issuer_certificate.get_pubkey().to_cryptography_key().verify(
                        sig,
                        tbs,
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
