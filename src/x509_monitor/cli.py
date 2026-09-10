import argparse
import asyncio
import json
import socket
import subprocess
import sys
import time
from pathlib import Path

from .benchmark import plot_benchmark, run_sweep
from .config import load_config
from .database import connect, list_scans, migrate, save_scan
from .evaluation import evaluate_ground_truth
from .history import compare_scans, initial_changes
from .reporting import changes_markdown, scan_markdown, scan_table, write_json
from .scanner import scan_async, scan_sequential


ROOT = Path(__file__).resolve().parents[2]


def _wait_for_lab(config_path, names=None, timeout=10.0):
    config = load_config(str(config_path))
    targets = [target for target in config.targets if names is None or target.name in names]
    deadline = time.monotonic() + timeout
    pending = list(targets)
    while pending and time.monotonic() < deadline:
        remaining = []
        for target in pending:
            try:
                with socket.create_connection((target.host, target.port), timeout=0.2): pass
            except OSError:
                remaining.append(target)
        pending = remaining
        if pending: time.sleep(0.1)
    if pending:
        raise RuntimeError("Lab endpoints did not become ready: " + ", ".join(target.name for target in pending))


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="x509-monitor", description="Allowlist-only X.509 exposure monitor")
    root.add_argument("--config", default=str(ROOT / "allowlist.yaml"), help="required explicit allowlist YAML")
    root.add_argument("--db", default=str(ROOT / "data" / "history.db"))
    commands = root.add_subparsers(dest="command", required=True)
    lab = commands.add_parser("lab"); lab.add_argument("action", choices=["generate", "start", "stop", "rotate"]); lab.add_argument("--target", default="valid"); lab.add_argument("--reuse-key", action="store_true")
    commands.add_parser("init-db")
    scan = commands.add_parser("scan"); scan.add_argument("--mode", choices=["v1", "v2"], default="v2"); scan.add_argument("--concurrency", type=int); scan.add_argument("--json"); scan.add_argument("--markdown")
    diff = commands.add_parser("diff"); diff.add_argument("--previous", type=int); diff.add_argument("--current", type=int); diff.add_argument("--json"); diff.add_argument("--markdown")
    report = commands.add_parser("report"); report.add_argument("--scan-id", type=int); report.add_argument("--json")
    evaluate = commands.add_parser("evaluate"); evaluate.add_argument("--scan-id", type=int); evaluate.add_argument("--manifest", default=str(ROOT / "lab" / "certs" / "ground_truth.json"))
    benchmark = commands.add_parser("benchmark"); benchmark.add_argument("--repeat-endpoints", type=int, default=3); benchmark.add_argument("--runs", type=int, default=3); benchmark.add_argument("--concurrency", default="1,5,10,25,50"); benchmark.add_argument("--output-dir", default=str(ROOT / "artifacts" / "benchmarks")); benchmark.add_argument("--manifest", default=str(ROOT / "lab" / "certs" / "ground_truth.json"))
    plot = commands.add_parser("plot"); plot.add_argument("json_path"); plot.add_argument("--output-dir", default=str(ROOT / "artifacts" / "plots"))
    return root


def _lab(args):
    generator = ROOT / "lab" / "generate_certs.py"
    if args.action == "generate": subprocess.run([sys.executable, str(generator)], check=True, cwd=ROOT)
    elif args.action == "rotate":
        command = [sys.executable, str(generator), "--rotate", args.target]
        if args.reuse_key: command.append("--reuse-key")
        subprocess.run(command, check=True, cwd=ROOT)
        subprocess.run(["docker", "compose", "build", "valid"], check=True, cwd=ROOT)
        subprocess.run(["docker", "compose", "up", "-d", "--force-recreate", args.target], check=True, cwd=ROOT)
        _wait_for_lab(args.config, {args.target})
    else:
        subprocess.run(["docker", "compose", "up", "-d", "--build"] if args.action == "start" else ["docker", "compose", "down"], check=True, cwd=ROOT)
        if args.action == "start": _wait_for_lab(args.config)


def _rows_to_results(connection, scan_id):
    # Evaluation is designed for fresh scan results; reconstruct only the relevant shape from DB.
    from .database import load_observations
    from .models import CertificateMetadata, ProbeResult, Target
    values = []
    for row in load_observations(connection, scan_id).values():
        item = ProbeResult(Target(row["name"], row["host"], row["port"], row["server_name"]), row["collected_at"], row["latency_ms"])
        item.findings = row["findings"]
        if row["certificate_fingerprint"]:
            item.certificate = CertificateMetadata(
                row["subject"], row["issuer"], row["sans"], "", "", row["not_after"], "", None,
                "", None, row["certificate_fingerprint"], row["spki_sha256"], "",
            )
        values.append(item)
    return values


def main(argv=None):
    args = parser().parse_args(argv)
    if args.command == "lab": return _lab(args)
    if args.command == "plot":
        for path in plot_benchmark(args.json_path, args.output_dir): print(path)
        return
    config = load_config(args.config)
    connection = connect(args.db); migrate(connection)
    if args.command == "init-db": print(f"Initialized {Path(args.db).resolve()}"); return
    if args.command == "scan":
        concurrency = args.concurrency or config.concurrency
        scan = scan_sequential(config) if args.mode == "v1" else asyncio.run(scan_async(config, concurrency))
        save_scan(connection, scan, str(config.path)); print(scan_table(scan)); print(f"scan_id={scan.scan_id} peak_concurrency={scan.peak_concurrency}/{scan.configured_concurrency}")
        if args.json: print(write_json(args.json, scan.to_dict()))
        if args.markdown:
            path = Path(args.markdown).resolve(); path.parent.mkdir(parents=True, exist_ok=True); path.write_text(scan_markdown(scan)); print(path)
        return
    scans = list_scans(connection)
    if args.command == "diff":
        current = args.current or (scans[-1]["id"] if scans else None)
        previous = args.previous or (scans[-2]["id"] if len(scans) > 1 else None)
        if current is None: raise SystemExit("No scans exist")
        changes = compare_scans(connection, previous, current, config.expiry_warning_days) if previous else initial_changes(connection, current)
        output = changes_markdown(changes, previous, current); print(output)
        if args.json: print(write_json(args.json, {"previous_scan_id": previous, "current_scan_id": current, "changes": changes}))
        if args.markdown:
            path = Path(args.markdown).resolve(); path.parent.mkdir(parents=True, exist_ok=True); path.write_text(output); print(path)
        return
    if args.command == "report":
        from .database import load_observations
        scan_id = args.scan_id or (scans[-1]["id"] if scans else None)
        if scan_id is None: raise SystemExit("No scans exist")
        payload = {"scan": next(row for row in scans if row["id"] == scan_id), "observations": list(load_observations(connection, scan_id).values())}
        print(json.dumps(payload, indent=2, default=str));
        if args.json: print(write_json(args.json, payload))
        return
    if args.command == "evaluate":
        print(json.dumps(evaluate_ground_truth(_rows_to_results(connection, args.scan_id or scans[-1]["id"]), args.manifest), indent=2)); return
    if args.command == "benchmark":
        concurrencies = [int(v) for v in args.concurrency.split(",")]
        payload = run_sweep(config, args.manifest, args.repeat_endpoints, concurrencies, args.runs, args.output_dir)
        print(json.dumps({"json": payload["json"], "csv": payload["csv"], "results": payload["results"]}, indent=2)); return


if __name__ == "__main__":
    main()
