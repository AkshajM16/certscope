from datetime import datetime, timedelta, timezone
from pathlib import Path

from x509_monitor.analyzer import analyze, evaluate_relationships
from x509_monitor.certificates import parse_certificate
from x509_monitor.config import load_config
from x509_monitor.models import CertificateMetadata, ProbeResult, Target


def metadata(not_before, not_after, cert_fp="AA", spki="BB", size=2048):
    return CertificateMetadata("CN=test", "CN=issuer", ["test.local"], "01", not_before.isoformat(), not_after.isoformat(), "sha256WithRSAEncryption", "sha256", "RSA", size, cert_fp, spki, "PEM")


def test_expiry_boundaries(project_root):
    config = load_config(str(project_root / "allowlist.yaml"))
    now = datetime(2030, 1, 1, tzinfo=timezone.utc)
    target = Target("test", "127.0.0.1", 443, "test.local")
    at_boundary = ProbeResult(target, now.isoformat(), 1, certificate=metadata(now - timedelta(days=1), now), hostname_valid=True, trust_valid=True)
    assert "expired" in {f["category"] for f in analyze(at_boundary, config, now)}
    future = ProbeResult(target, now.isoformat(), 1, certificate=metadata(now + timedelta(seconds=1), now + timedelta(days=60)), hostname_valid=True, trust_valid=True)
    assert "not_yet_valid" in {f["category"] for f in analyze(future, config, now)}
    warning = ProbeResult(target, now.isoformat(), 1, certificate=metadata(now - timedelta(days=1), now + timedelta(days=30)), hostname_valid=True, trust_valid=True)
    assert "impending_expiry" in {f["category"] for f in analyze(warning, config, now)}


def test_clustering_distinguishes_certificate_and_key():
    now = datetime.now(timezone.utc)
    values = []
    for name, cert_fp, spki in [("a", "CERT1", "KEY1"), ("b", "CERT1", "KEY1"), ("c", "CERT2", "KEY2"), ("d", "CERT3", "KEY2")]:
        values.append(ProbeResult(Target(name, "127.0.0.1", 443, "x"), now.isoformat(), 1, certificate=metadata(now, now + timedelta(days=1), cert_fp, spki)))
    groups = evaluate_relationships(values)
    assert groups["shared_certificates"][0]["targets"] == ["a", "b"]
    assert {tuple(g["targets"]) for g in groups["shared_spkis"]} == {("a", "b"), ("c", "d")}
