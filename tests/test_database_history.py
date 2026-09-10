from datetime import datetime, timedelta, timezone

from x509_monitor.database import connect, migrate, save_scan
from x509_monitor.history import compare_scans
from x509_monitor.models import CertificateMetadata, ProbeResult, ScanResult, Target


def cert(fp, spki, issuer="CN=CA", sans=None):
    now = datetime.now(timezone.utc)
    return CertificateMetadata("CN=x", issuer, sans or ["x.local"], fp, (now - timedelta(days=1)).isoformat(), (now + timedelta(days=365)).isoformat(), "sha256", "sha256", "RSA", 2048, fp, spki, "PEM")


def scan(mode, target, certificate):
    now = datetime.now(timezone.utc).isoformat()
    return ScanResult(mode, now, now, 1, 1, [ProbeResult(target, now, 1, certificate=certificate, hostname_valid=True, trust_valid=True)])


def test_database_deduplication_and_rotation_diff(tmp_path, project_root):
    db = connect(str(tmp_path / "history.db")); migrate(db, str(project_root / "sql" / "migrations"))
    target = Target("x", "127.0.0.1", 443, "x.local")
    first = scan("v1", target, cert("CERT1", "KEY1")); first_id = save_scan(db, first, "config")
    second = scan("v2", target, cert("CERT2", "KEY1")); second_id = save_scan(db, second, "config")
    assert db.execute("SELECT COUNT(*) FROM certificates").fetchone()[0] == 2
    changes = {item["category"] for item in compare_scans(db, first_id, second_id)}
    assert {"certificate_rotation", "key_reuse"} <= changes
    assert "key_rotation" not in changes


def test_key_rotation_and_disappearance(tmp_path, project_root):
    db = connect(str(tmp_path / "history.db")); migrate(db, str(project_root / "sql" / "migrations"))
    target = Target("x", "127.0.0.1", 443, "x.local")
    first = scan("v1", target, cert("CERT1", "KEY1")); a = save_scan(db, first, "config")
    second = scan("v2", target, cert("CERT2", "KEY2")); b = save_scan(db, second, "config")
    changes = {item["category"] for item in compare_scans(db, a, b)}
    assert {"certificate_rotation", "key_rotation"} <= changes


def test_disappearance_and_reappearance(tmp_path, project_root):
    db = connect(str(tmp_path / "history.db")); migrations = str(project_root / "sql" / "migrations")
    migrate(db, migrations); migrate(db, migrations)
    target = Target("x", "127.0.0.1", 443, "x.local")
    first = scan("v1", target, cert("CERT1", "KEY1")); a = save_scan(db, first, "config")
    now = datetime.now(timezone.utc).isoformat()
    empty = ScanResult("v2", now, now, 1, 0, []); b = save_scan(db, empty, "config")
    third = scan("v2", target, cert("CERT1", "KEY1")); c = save_scan(db, third, "config")
    assert [item["category"] for item in compare_scans(db, a, b)] == ["disappearance"]
    assert [item["category"] for item in compare_scans(db, b, c)] == ["reappearance"]
    assert db.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0] == 1


def test_packaged_and_documented_migrations_match(project_root):
    packaged = project_root / "src" / "x509_monitor" / "sql" / "001_initial.sql"
    documented = project_root / "sql" / "migrations" / "001_initial.sql"
    assert packaged.read_bytes() == documented.read_bytes()
