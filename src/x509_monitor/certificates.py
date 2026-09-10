import base64
import hashlib
import ipaddress
import ssl
from datetime import datetime, timezone
from typing import Iterable, List

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa
from cryptography.x509.oid import ExtensionOID

from .models import CertificateMetadata


def sha256_colon(data: bytes) -> str:
    return ":".join(f"{byte:02X}" for byte in hashlib.sha256(data).digest())


def _public_key_details(key):
    if isinstance(key, rsa.RSAPublicKey):
        return "RSA", key.key_size
    if isinstance(key, dsa.DSAPublicKey):
        return "DSA", key.key_size
    if isinstance(key, ec.EllipticCurvePublicKey):
        return "EC", key.key_size
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "Ed25519", 256
    if isinstance(key, ed448.Ed448PublicKey):
        return "Ed448", 456
    return type(key).__name__, getattr(key, "key_size", None)


def _utc_iso(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def parse_certificate(der: bytes) -> CertificateMetadata:
    cert = x509.load_der_x509_certificate(der)
    key = cert.public_key()
    algorithm, key_size = _public_key_details(key)
    spki = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        sans = [str(item.value) for item in san]
    except x509.ExtensionNotFound:
        sans = []
    try:
        signature_hash = cert.signature_hash_algorithm.name
    except Exception:
        signature_hash = None
    return CertificateMetadata(
        subject=cert.subject.rfc4514_string(), issuer=cert.issuer.rfc4514_string(),
        sans=sans, serial=f"{cert.serial_number:X}",
        not_before=_utc_iso(cert.not_valid_before_utc), not_after=_utc_iso(cert.not_valid_after_utc),
        signature_algorithm=cert.signature_algorithm_oid._name or cert.signature_algorithm_oid.dotted_string,
        signature_hash=signature_hash, public_key_algorithm=algorithm, public_key_size=key_size,
        certificate_fingerprint=sha256_colon(der), spki_fingerprint=sha256_colon(spki),
        pem=cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
    )


def _dns_match(pattern: str, hostname: str) -> bool:
    pattern, hostname = pattern.rstrip(".").lower(), hostname.rstrip(".").lower()
    if "*" not in pattern:
        return pattern == hostname
    labels = pattern.split(".")
    return labels[0] == "*" and all("*" not in label for label in labels[1:]) and len(labels) == len(hostname.split(".")) and labels[1:] == hostname.split(".")[1:]


def hostname_matches(sans: Iterable[str], hostname: str) -> bool:
    values = list(sans)
    try:
        expected_ip = ipaddress.ip_address(hostname)
    except ValueError:
        return any(_dns_match(value, hostname) for value in values)
    for value in values:
        try:
            if ipaddress.ip_address(value) == expected_ip:
                return True
        except ValueError:
            continue
    return False


def extract_chain_fingerprints(tls_socket) -> List[str]:
    """Return chain fingerprints when the interpreter exposes OpenSSL's chain API."""
    getter = getattr(getattr(tls_socket, "_sslobj", None), "get_unverified_chain", None)
    if getter is None:
        return []
    fingerprints = []
    try:
        for item in getter():
            if isinstance(item, bytes):
                der = item
            else:
                pem = item.public_bytes()
                der = ssl.PEM_cert_to_DER_cert(pem.decode() if isinstance(pem, bytes) else pem)
                der = base64.b64decode(der) if isinstance(der, str) else der
            fingerprints.append(sha256_colon(der))
    except Exception:
        return []
    return fingerprints
