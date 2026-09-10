import json
from pathlib import Path
from typing import Any, Dict, Iterable, List

from tabulate import tabulate

from .analyzer import evaluate_relationships
from .models import ScanResult


def scan_table(scan: ScanResult) -> str:
    rows = []
    for item in scan.results:
        rows.append([
            item.target.name,
            item.certificate.certificate_fingerprint[:17] + "…" if item.certificate else "—",
            item.certificate.spki_fingerprint[:17] + "…" if item.certificate else "—",
            item.tls_version or "—", "yes" if item.hostname_valid else "no" if item.hostname_valid is False else "—",
            "yes" if item.trust_valid else "no" if item.trust_valid is False else "—",
            ", ".join(f["category"] for f in item.findings) or "none", f"{item.latency_ms:.1f}",
        ])
    return tabulate(rows, headers=["Target", "Cert SHA-256", "SPKI SHA-256", "TLS", "Host", "Trust", "Findings", "ms"], tablefmt="github")


def scan_markdown(scan: ScanResult) -> str:
    relations = evaluate_relationships(scan.results)
    lines = [f"# X.509 scan {scan.scan_id or '(unsaved)'}", "", scan_table(scan), "", "## Relationship view", ""]
    for label, groups in (("Identical certificate", relations["shared_certificates"]), ("Identical SPKI/key", relations["shared_spkis"])):
        lines.append(f"- {label}")
        if not groups:
            lines.append("  - none")
        for group in groups:
            lines.append(f"  - `{group['fingerprint']}`")
            for target in group["targets"]:
                lines.append(f"    - {target}")
    lines += ["", f"Mode: `{scan.mode}`; configured concurrency: {scan.configured_concurrency}; observed peak: {scan.peak_concurrency}.", ""]
    return "\n".join(lines)


def changes_markdown(changes: List[Dict[str, Any]], previous: int = None, current: int = None) -> str:
    title = f"# Changes: scan {previous} → {current}" if previous else f"# First-seen inventory: scan {current}"
    rows = [[item["target"], item["category"], item["detail"]] for item in changes]
    return title + "\n\n" + (tabulate(rows, headers=["Target", "Change", "Detail"], tablefmt="github") if rows else "No changes detected.") + "\n"


def write_json(path: str, value: Any) -> Path:
    output = Path(path).expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return output
