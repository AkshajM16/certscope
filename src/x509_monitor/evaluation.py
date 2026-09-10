import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Set, Tuple

from .analyzer import evaluate_relationships
from .models import ProbeResult


DETECTOR_CATEGORIES = {"expired", "hostname_mismatch", "untrusted", "not_yet_valid", "weak_public_key", "weak_signature_algorithm"}


def _metrics(expected: Set[Tuple[str, str]], observed: Set[Tuple[str, str]]) -> Dict[str, Any]:
    correct = expected & observed
    missed = sorted(expected - observed)
    incorrect = sorted(observed - expected)
    precision = len(correct) / len(observed) if observed else (1.0 if not expected else 0.0)
    recall = len(correct) / len(expected) if expected else 1.0
    return {
        "true_positive_count": len(correct), "expected_count": len(expected), "observed_count": len(observed),
        "precision": precision, "recall": recall,
        "missed": [{"target": t, "category": c} for t, c in missed],
        "incorrect": [{"target": t, "category": c} for t, c in incorrect],
    }


def evaluate_ground_truth(results: List[ProbeResult], manifest_path: str) -> Dict[str, Any]:
    manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    expected: Set[Tuple[str, str]] = set()
    for name, info in manifest["targets"].items():
        expected.update((name, category) for category in info["expected_findings"] if category in DETECTOR_CATEGORIES)
    observed: Set[Tuple[str, str]] = set()
    for result in results:
        base_name = result.target.name.split("#", 1)[0]
        observed.update((base_name, f["category"]) for f in result.findings if f["category"] in DETECTOR_CATEGORIES)
    detector = _metrics(expected, observed)

    relationships = evaluate_relationships(results)
    observed_shared_cert = {tuple(sorted(item["targets"])) for item in relationships["shared_certificates"]}
    observed_shared_spki = {tuple(sorted(item["targets"])) for item in relationships["shared_spkis"]}
    expected_shared_cert = {tuple(sorted(group)) for group in manifest["relationships"]["shared_certificates"]}
    expected_shared_spki = {tuple(sorted(group)) for group in manifest["relationships"]["shared_spkis"]}
    # Relationship evaluation is meaningful for the un-repeated canonical allowlist.
    relationship_eval = {
        "shared_certificates": _set_comparison(expected_shared_cert, observed_shared_cert),
        "shared_spkis": _set_comparison(expected_shared_spki, observed_shared_spki),
    }
    return {"detectors": detector, "relationships": relationship_eval}


def _set_comparison(expected: Set[Tuple[str, ...]], observed: Set[Tuple[str, ...]]) -> Dict[str, Any]:
    tp = expected & observed
    return {
        "precision": len(tp) / len(observed) if observed else (1.0 if not expected else 0.0),
        "recall": len(tp) / len(expected) if expected else 1.0,
        "missed": [list(item) for item in sorted(expected - observed)],
        "incorrect": [list(item) for item in sorted(observed - expected)],
    }
