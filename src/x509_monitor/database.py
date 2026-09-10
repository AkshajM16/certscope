import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .models import ProbeResult, ScanResult


def connect(path: str) -> sqlite3.Connection:
    db_path = Path(path).expanduser().resolve()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(db_path))
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def migrate(connection: sqlite3.Connection, migrations_dir: Optional[str] = None) -> None:
    if migrations_dir is None:
        migrations = Path(__file__).resolve().parent / "sql"
    else:
        migrations = Path(migrations_dir)
    connection.execute("CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)")
    applied = {row[0] for row in connection.execute("SELECT version FROM schema_migrations")}
    for path in sorted(migrations.glob("*.sql")):
        version = int(path.name.split("_", 1)[0])
        if version not in applied:
            connection.executescript(path.read_text(encoding="utf-8"))
            connection.execute(
                "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                (version, datetime.now(timezone.utc).isoformat()),
            )
    connection.commit()


def _bool(value: Optional[bool]) -> Optional[int]:
    return None if value is None else int(value)


def save_scan(connection: sqlite3.Connection, scan: ScanResult, config_path: str) -> int:
    cursor = connection.execute(
        "INSERT INTO scans(started_at, completed_at, mode, configured_concurrency, peak_concurrency, config_path) VALUES (?, ?, ?, ?, ?, ?)",
        (scan.started_at, scan.completed_at, scan.mode, scan.configured_concurrency, scan.peak_concurrency, config_path),
    )
    scan_id = int(cursor.lastrowid)
    for result in scan.results:
        target = result.target
        connection.execute(
            "INSERT INTO endpoints(identity, name, host, port, server_name) VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(identity) DO UPDATE SET name=excluded.name, host=excluded.host, port=excluded.port, server_name=excluded.server_name",
            (target.identity, target.name, target.host, target.port, target.server_name),
        )
        endpoint_id = connection.execute("SELECT id FROM endpoints WHERE identity=?", (target.identity,)).fetchone()[0]
        cert = result.certificate
        if cert:
            connection.execute(
                "INSERT OR IGNORE INTO certificates VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (cert.certificate_fingerprint, cert.spki_fingerprint, cert.subject, cert.issuer,
                 json.dumps(cert.sans), cert.serial, cert.not_before, cert.not_after,
                 cert.signature_algorithm, cert.signature_hash, cert.public_key_algorithm,
                 cert.public_key_size, cert.pem),
            )
        obs = connection.execute(
            "INSERT INTO observations(scan_id, endpoint_id, collected_at, certificate_fingerprint, chain_fingerprints_json, tls_version, cipher, hostname_valid, trust_valid, verification_error, latency_ms, error_class, error_message) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (scan_id, endpoint_id, result.collected_at,
             cert.certificate_fingerprint if cert else None, json.dumps(result.chain_fingerprints),
             result.tls_version, result.cipher, _bool(result.hostname_valid), _bool(result.trust_valid),
             result.verification_error, result.latency_ms, result.error_class, result.error_message),
        )
        observation_id = int(obs.lastrowid)
        for finding in result.findings:
            connection.execute(
                "INSERT OR IGNORE INTO findings(observation_id, category, severity, detail) VALUES (?, ?, ?, ?)",
                (observation_id, finding["category"], finding["severity"], finding["detail"]),
            )
    connection.commit()
    scan.scan_id = scan_id
    return scan_id


def list_scans(connection: sqlite3.Connection) -> List[Dict[str, Any]]:
    return [dict(row) for row in connection.execute("SELECT * FROM scans ORDER BY id")]


def load_observations(connection: sqlite3.Connection, scan_id: int) -> Dict[str, Dict[str, Any]]:
    query = """
      SELECT e.identity, e.name, e.host, e.port, e.server_name, o.*, c.spki_sha256,
             c.subject, c.issuer, c.sans_json, c.not_after
      FROM observations o JOIN endpoints e ON e.id=o.endpoint_id
      LEFT JOIN certificates c ON c.fingerprint_sha256=o.certificate_fingerprint
      WHERE o.scan_id=?
    """
    values: Dict[str, Dict[str, Any]] = {}
    for row in connection.execute(query, (scan_id,)):
        item = dict(row)
        item["sans"] = json.loads(item.pop("sans_json") or "[]")
        item["findings"] = [dict(f) for f in connection.execute(
            "SELECT category, severity, detail FROM findings WHERE observation_id=? ORDER BY category", (item["id"],)
        )]
        values[item["identity"]] = item
    return values
