#!/usr/bin/env python3
"""Generate disposable lab-only certificates and a ground-truth manifest."""
import argparse
import json
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


ROOT = Path(__file__).resolve().parent
CERTS = ROOT / "certs"
TARGETS = {
    "valid": ("valid.lab.test", "valid.lab.test", "ca", "valid"),
    "expired": ("expired.lab.test", "expired.lab.test", "ca", "expired"),
    "hostname-mismatch": ("mismatch.lab.test", "unexpected.lab.test", "ca", "mismatch"),
    "self-signed": ("selfsigned.lab.test", "selfsigned.lab.test", "self", "self_signed"),
    "shared-cert-a": ("shared.lab.test", "shared.lab.test", "shared-cert", "shared_certificate"),
    "shared-cert-b": ("shared.lab.test", "shared.lab.test", "shared-cert", "shared_certificate"),
    "shared-spki-a": ("spki-a.lab.test", "spki-a.lab.test", "shared-spki", "shared_spki"),
    "shared-spki-b": ("spki-b.lab.test", "spki-b.lab.test", "shared-spki", "shared_spki"),
}


def save_key(path: Path, key) -> None:
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    path.chmod(0o600)


def load_key(path: Path):
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def name(common_name: str) -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "X509 Monitor Disposable Lab"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])


def issue(common_name, san_name, key, issuer_cert, issuer_key, not_before, not_after, serial=None):
    builder = (
        x509.CertificateBuilder().subject_name(name(common_name)).issuer_name(issuer_cert.subject)
        .public_key(key.public_key()).serial_number(serial or x509.random_serial_number())
        .not_valid_before(not_before).not_valid_after(not_after)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(san_name)]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(False, False, True, False, False, False, False, False, False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False)
    )
    return builder.sign(issuer_key, hashes.SHA256())


def create_ca(now):
    ca_dir = CERTS / "ca"
    ca_dir.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = (
        x509.CertificateBuilder().subject_name(name("X509 Monitor Lab CA")).issuer_name(name("X509 Monitor Lab CA"))
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    save_key(ca_dir / "ca-key.pem", key)
    (ca_dir / "ca.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return key, cert


def fingerprints(cert):
    cert_fp = cert.fingerprint(hashes.SHA256()).hex(":").upper()
    spki = cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    digest = hashes.Hash(hashes.SHA256()); digest.update(spki)
    return cert_fp, digest.finalize().hex(":").upper()


def write_endpoint(endpoint: str, cert, key, ca_cert=None):
    directory = CERTS / endpoint
    directory.mkdir(parents=True, exist_ok=True)
    leaf = cert.public_bytes(serialization.Encoding.PEM)
    chain = leaf + (ca_cert.public_bytes(serialization.Encoding.PEM) if ca_cert else b"")
    (directory / "cert.pem").write_bytes(chain)
    save_key(directory / "key.pem", key)


def generate_all():
    if CERTS.exists():
        shutil.rmtree(CERTS)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    ca_key, ca_cert = create_ca(now)
    shared_cert_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    shared_spki_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    shared_cert = None
    manifest = {
        "generated_at": now.isoformat(), "lab_only": True,
        "note": "Keys are disposable generated fixtures; never reuse them outside this lab.",
        "targets": {}, "relationships": {
            "shared_certificates": [["shared-cert-a", "shared-cert-b"]],
            "shared_spkis": [["shared-cert-a", "shared-cert-b"], ["shared-spki-a", "shared-spki-b"]],
            "distinct_certificates_same_spki": [["shared-spki-a", "shared-spki-b"]],
        },
    }
    for endpoint, (expected_name, cert_san, kind, condition) in TARGETS.items():
        if kind == "shared-cert" and shared_cert is not None:
            cert, key = shared_cert, shared_cert_key
        else:
            key = shared_cert_key if kind == "shared-cert" else shared_spki_key if kind == "shared-spki" else rsa.generate_private_key(public_exponent=65537, key_size=2048)
            if kind == "self":
                issuer_key = key
                issuer_cert = type("Issuer", (), {"subject": name(cert_san)})()
            else:
                issuer_key, issuer_cert = ca_key, ca_cert
            before = now - timedelta(days=60) if condition == "expired" else now - timedelta(days=1)
            after = now - timedelta(days=1) if condition == "expired" else now + timedelta(days=365)
            cert = issue(cert_san, cert_san, key, issuer_cert, issuer_key, before, after)
            if kind == "shared-cert":
                shared_cert = cert
        write_endpoint(endpoint, cert, key, None if kind == "self" else ca_cert)
        cert_fp, spki_fp = fingerprints(cert)
        expected_findings = []
        if condition == "expired": expected_findings += ["expired", "untrusted"]
        if condition == "mismatch": expected_findings += ["hostname_mismatch"]
        if condition == "self_signed": expected_findings += ["untrusted"]
        manifest["targets"][endpoint] = {
            "expected_server_name": expected_name, "certificate_san": cert_san,
            "condition": condition, "certificate_fingerprint": cert_fp,
            "spki_fingerprint": spki_fp, "expected_findings": expected_findings,
            "hostname_valid": condition != "mismatch", "trust_valid": condition not in ("expired", "self_signed"),
        }
    (CERTS / "ground_truth.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"Generated {len(TARGETS)} endpoint certificates in {CERTS}")


def rotate(endpoint: str, reuse_key: bool):
    manifest_path = CERTS / "ground_truth.json"
    if not manifest_path.exists():
        raise SystemExit("Run lab generation first")
    if endpoint not in TARGETS:
        raise SystemExit(f"Unknown endpoint: {endpoint}")
    manifest = json.loads(manifest_path.read_text())
    ca_key = load_key(CERTS / "ca" / "ca-key.pem")
    ca_cert = x509.load_pem_x509_certificate((CERTS / "ca" / "ca.pem").read_bytes())
    old_key_path = CERTS / endpoint / "key.pem"
    key = load_key(old_key_path) if reuse_key else rsa.generate_private_key(public_exponent=65537, key_size=2048)
    expected_name, cert_san, kind, condition = TARGETS[endpoint]
    now = datetime.now(timezone.utc).replace(microsecond=0)
    cert = issue(cert_san, cert_san, key, ca_cert, ca_key, now - timedelta(minutes=1), now + timedelta(days=365))
    write_endpoint(endpoint, cert, key, ca_cert)
    cert_fp, spki_fp = fingerprints(cert)
    manifest["targets"][endpoint].update(certificate_fingerprint=cert_fp, spki_fingerprint=spki_fp, condition="rotated")
    manifest["last_rotation"] = {"target": endpoint, "at": now.isoformat(), "reused_key": reuse_key}
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"Rotated {endpoint}; reused_key={reuse_key}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--rotate", choices=sorted(TARGETS))
    parser.add_argument("--reuse-key", action="store_true")
    args = parser.parse_args()
    rotate(args.rotate, args.reuse_key) if args.rotate else generate_all()


if __name__ == "__main__":
    main()
