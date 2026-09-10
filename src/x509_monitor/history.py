from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from .database import load_observations


def compare_scans(connection, previous_id: int, current_id: int, expiry_days: int = 30) -> List[Dict[str, Any]]:
    previous = load_observations(connection, previous_id)
    current = load_observations(connection, current_id)
    changes: List[Dict[str, Any]] = []
    all_prior = {row[0] for row in connection.execute(
        "SELECT DISTINCT e.identity FROM observations o JOIN endpoints e ON e.id=o.endpoint_id WHERE o.scan_id < ?", (previous_id,)
    )}
    for identity in sorted(set(previous) | set(current)):
        before, after = previous.get(identity), current.get(identity)
        if before is None and after is not None:
            category = "reappearance" if identity in all_prior else "first_seen"
            changes.append({"target": identity, "category": category, "detail": f"present in scan {current_id}"})
            continue
        if before is not None and after is None:
            changes.append({"target": identity, "category": "disappearance", "detail": f"absent from scan {current_id}"})
            continue
        if before["certificate_fingerprint"] and not after["certificate_fingerprint"]:
            changes.append({"target": identity, "category": "disappearance", "detail": f"certificate unavailable in scan {current_id}: {after.get('error_class') or 'unknown error'}"})
            continue
        if not before["certificate_fingerprint"] and after["certificate_fingerprint"]:
            changes.append({"target": identity, "category": "reappearance", "detail": f"certificate available again in scan {current_id}"})
            continue
        if before["certificate_fingerprint"] != after["certificate_fingerprint"]:
            changes.append({"target": identity, "category": "certificate_rotation", "detail": "leaf fingerprint changed"})
            if before["spki_sha256"] == after["spki_sha256"] and after["spki_sha256"]:
                changes.append({"target": identity, "category": "key_reuse", "detail": "new certificate reuses the previous SPKI"})
            else:
                changes.append({"target": identity, "category": "key_rotation", "detail": "SPKI fingerprint changed"})
        if before["issuer"] != after["issuer"]:
            changes.append({"target": identity, "category": "unexpected_issuer_change", "detail": f"{before['issuer']} -> {after['issuer']}"})
        if before["sans"] != after["sans"]:
            changes.append({"target": identity, "category": "unexpected_san_change", "detail": f"{before['sans']} -> {after['sans']}"})
        if after.get("not_after"):
            deadline = datetime.fromisoformat(after["not_after"])
            if deadline <= datetime.now(timezone.utc) + timedelta(days=expiry_days):
                changes.append({"target": identity, "category": "impending_expiry", "detail": after["not_after"]})
    return changes


def initial_changes(connection, current_id: int) -> List[Dict[str, Any]]:
    return [
        {"target": identity, "category": "first_seen", "detail": f"first observation in scan {current_id}"}
        for identity in sorted(load_observations(connection, current_id))
    ]
