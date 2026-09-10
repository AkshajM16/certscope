import ssl
from datetime import datetime, timedelta, timezone

from cryptography import x509

from x509_monitor.certificates import hostname_matches, parse_certificate, sha256_colon


def test_parse_and_fingerprints(generated_lab):
    pem = (generated_lab / "valid" / "cert.pem").read_text()
    leaf = pem.split("-----END CERTIFICATE-----")[0] + "-----END CERTIFICATE-----\n"
    der = ssl.PEM_cert_to_DER_cert(leaf)
    cert = parse_certificate(der)
    assert cert.subject.startswith("CN=valid.lab.test")
    assert cert.sans == ["valid.lab.test"]
    assert cert.public_key_algorithm == "RSA"
    assert cert.public_key_size == 2048
    assert cert.certificate_fingerprint == sha256_colon(der)
    assert cert.certificate_fingerprint != cert.spki_fingerprint


def test_hostname_san_logic():
    assert hostname_matches(["www.example.test"], "www.example.test")
    assert hostname_matches(["*.example.test"], "api.example.test")
    assert not hostname_matches(["*.example.test"], "deep.api.example.test")
    assert not hostname_matches(["bad.example.test"], "good.example.test")
    assert hostname_matches(["127.0.0.1"], "127.0.0.1")
    assert not hostname_matches(["localhost"], "127.0.0.1")
