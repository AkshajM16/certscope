import asyncio
import csv
import json
import platform
import ssl
import statistics
import sys
import time
import tracemalloc
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List

import cryptography

from .config import Config
from .evaluation import evaluate_ground_truth
from .models import Target
from .scanner import scan_async, scan_sequential


def percentile(values: List[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round((len(ordered) - 1) * fraction))))
    return ordered[index]


def repeated_config(config: Config, repeats: int) -> Config:
    targets = [
        Target(f"{target.name}#{iteration + 1}" if repeats > 1 else target.name, target.host, target.port, target.server_name)
        for iteration in range(repeats) for target in config.targets
    ]
    return replace(config, targets=targets)


def _one(config: Config, mode: str, concurrency: int, manifest: str) -> Dict[str, Any]:
    tracemalloc.start()
    started = time.perf_counter()
    scan = scan_sequential(config) if mode == "v1" else asyncio.run(scan_async(config, concurrency))
    wall = time.perf_counter() - started
    _, peak_memory = tracemalloc.get_traced_memory(); tracemalloc.stop()
    latencies = [r.latency_ms for r in scan.results]
    error_counts: Dict[str, int] = {}
    for result in scan.results:
        key = result.error_class or "none"
        error_counts[key] = error_counts.get(key, 0) + 1
    detector_eval = evaluate_ground_truth(scan.results, manifest)["detectors"]
    truth = json.loads(Path(manifest).read_text(encoding="utf-8"))
    unchanged_correct = sum(
        bool(result.certificate)
        and result.certificate.certificate_fingerprint
        == truth["targets"][result.target.name.split("#", 1)[0]]["certificate_fingerprint"]
        for result in scan.results
    )
    return {
        "mode": mode, "concurrency": concurrency, "endpoint_count": len(scan.results),
        "wall_seconds": wall, "endpoints_per_second": len(scan.results) / wall if wall else 0.0,
        "p50_latency_ms": percentile(latencies, 0.50), "p95_latency_ms": percentile(latencies, 0.95),
        "mean_latency_ms": statistics.mean(latencies) if latencies else 0.0,
        "peak_active_probes": scan.peak_concurrency, "peak_tracemalloc_bytes": peak_memory,
        "error_classification_counts": error_counts,
        "detector_precision": detector_eval["precision"], "detector_recall": detector_eval["recall"],
        "change_detection_accuracy": unchanged_correct / len(scan.results) if scan.results else 1.0,
        "change_detection_scope": "no-change replay against current generated manifest",
        "missed": detector_eval["missed"], "incorrect": detector_eval["incorrect"],
    }


def run_sweep(config: Config, manifest: str, repeats: int, concurrencies: Iterable[int], runs: int, output_dir: str) -> Dict[str, Any]:
    expanded = repeated_config(config, repeats)
    rows = []
    for run_number in range(1, runs + 1):
        value = _one(expanded, "v1", 1, manifest); value["run"] = run_number; rows.append(value)
        for concurrency in concurrencies:
            value = _one(expanded, "v2", concurrency, manifest); value["run"] = run_number; rows.append(value)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    metadata = {
        "timestamp": stamp, "scope": "local Docker Compose lab only", "repeats_per_seeded_endpoint": repeats,
        "runs": runs, "config": str(config.path), "timeout_seconds": config.timeout_seconds,
        "platform": platform.platform(), "processor": platform.processor(), "python": sys.version,
        "openssl": ssl.OPENSSL_VERSION, "cryptography": cryptography.__version__,
    }
    payload = {"metadata": metadata, "results": rows}
    directory = Path(output_dir).resolve(); directory.mkdir(parents=True, exist_ok=True)
    json_path = directory / f"benchmark-{stamp}.json"
    csv_path = directory / f"benchmark-{stamp}.csv"
    json_path.write_text(json.dumps(payload, indent=2) + "\n")
    flat_keys = [k for k, v in rows[0].items() if not isinstance(v, (dict, list))] if rows else []
    with csv_path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=flat_keys, lineterminator="\n")
        writer.writeheader(); writer.writerows({key: row[key] for key in flat_keys} for row in rows)
    return {"json": str(json_path), "csv": str(csv_path), **payload}


def plot_benchmark(json_path: str, output_dir: str) -> List[str]:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    payload = json.loads(Path(json_path).read_text())
    rows = [row for row in payload["results"] if row["mode"] == "v2"]
    grouped: Dict[int, List[Dict[str, Any]]] = {}
    for row in rows:
        grouped.setdefault(int(row["concurrency"]), []).append(row)
    x = sorted(grouped)
    throughput = [statistics.mean(r["endpoints_per_second"] for r in grouped[c]) for c in x]
    p50 = [statistics.mean(r["p50_latency_ms"] for r in grouped[c]) for c in x]
    p95 = [statistics.mean(r["p95_latency_ms"] for r in grouped[c]) for c in x]
    directory = Path(output_dir).resolve(); directory.mkdir(parents=True, exist_ok=True)
    stamp = payload["metadata"]["timestamp"]
    paths = []
    fig, ax = plt.subplots(figsize=(7, 4)); ax.plot(x, throughput, marker="o"); ax.set(xlabel="Configured concurrency", ylabel="Endpoints / second", title="Local-lab throughput vs concurrency"); ax.grid(alpha=.3); fig.tight_layout()
    path = directory / f"throughput-{stamp}.png"; fig.savefig(path, dpi=160); plt.close(fig); paths.append(str(path))
    fig, ax = plt.subplots(figsize=(7, 4)); ax.plot(x, p50, marker="o", label="p50"); ax.plot(x, p95, marker="o", label="p95"); ax.set(xlabel="Configured concurrency", ylabel="Probe latency (ms)", title="Local-lab latency vs concurrency"); ax.grid(alpha=.3); ax.legend(); fig.tight_layout()
    path = directory / f"latency-{stamp}.png"; fig.savefig(path, dpi=160); plt.close(fig); paths.append(str(path))
    return paths
