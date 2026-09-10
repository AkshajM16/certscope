from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from .config import Config
from .models import ProbeResult


def finding(category: str, severity: str, detail: str) -> Dict[str, Any]:
    return {"category": category, "severity": severity, "detail": detail}


def analyze(result: ProbeResult, config: Config, now: datetime = None) -> List[Dict[str, Any]]:
    now = now or datetime.now(timezone.utc)
    findings: List[Dict[str, Any]] = []
    if result.error_class:
        return [finding("connection_failure", "high", f"{result.error_class}: {result.error_message}")]
    cert = result.certificate
    if cert is None:
        return [finding("connection_failure", "high", "TLS peer supplied no leaf certificate")]
    not_before = datetime.fromisoformat(cert.not_before)
    not_after = datetime.fromisoformat(cert.not_after)
    if now < not_before:
        findings.append(finding("not_yet_valid", "high", f"certificate starts {cert.not_before}"))
    if now >= not_after:
        findings.append(finding("expired", "critical", f"certificate expired {cert.not_after}"))
    elif not_after <= now + timedelta(days=config.expiry_warning_days):
        findings.append(finding("impending_expiry", "medium", f"certificate expires {cert.not_after}"))
    if result.hostname_valid is False:
        findings.append(finding("hostname_mismatch", "high", f"SANs {cert.sans!r} do not match {result.target.server_name}"))
    if result.trust_valid is False:
        findings.append(finding("untrusted", "high", result.verification_error or "certificate verification failed"))
    minimum = config.weak_key_rules.get(cert.public_key_algorithm)
    if minimum and (cert.public_key_size or 0) < minimum:
        findings.append(finding("weak_public_key", "high", f"{cert.public_key_algorithm} {cert.public_key_size} < {minimum} bits"))
    if cert.signature_hash and cert.signature_hash.lower() in config.weak_signature_hashes:
        findings.append(finding("weak_signature_algorithm", "high", cert.signature_algorithm))
    return findings


def evaluate_relationships(results: List[ProbeResult]) -> Dict[str, List[Dict[str, Any]]]:
    cert_groups: Dict[str, List[str]] = {}
    spki_groups: Dict[str, List[str]] = {}
    for result in results:
        if result.certificate:
            cert_groups.setdefault(result.certificate.certificate_fingerprint, []).append(result.target.name)
            spki_groups.setdefault(result.certificate.spki_fingerprint, []).append(result.target.name)
    return {
        "shared_certificates": [
            {"fingerprint": key, "targets": sorted(values)}
            for key, values in sorted(cert_groups.items()) if len(values) > 1
        ],
        "shared_spkis": [
            {"fingerprint": key, "targets": sorted(values),
             "certificate_count": len({r.certificate.certificate_fingerprint for r in results if r.certificate and r.certificate.spki_fingerprint == key})}
            for key, values in sorted(spki_groups.items()) if len(values) > 1
        ],
    }
