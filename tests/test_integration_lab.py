import asyncio
import json

import pytest

from x509_monitor.analyzer import evaluate_relationships
from x509_monitor.config import load_config
from x509_monitor.evaluation import evaluate_ground_truth
from x509_monitor.scanner import scan_async, scan_sequential


@pytest.mark.integration
def test_every_seeded_condition_and_ground_truth(project_root, generated_lab, lab_running):
    config = load_config(str(project_root / "allowlist.yaml"))
    manifest = json.loads((generated_lab / "ground_truth.json").read_text())
    scan = asyncio.run(scan_async(config, 3))
    by_name = {result.target.name: result for result in scan.results}
    assert scan.peak_concurrency <= 3
    assert set(by_name) == set(manifest["targets"])
    for name, expected in manifest["targets"].items():
        actual = by_name[name]
        assert actual.error_class is None
        assert actual.certificate.certificate_fingerprint == expected["certificate_fingerprint"]
        assert actual.certificate.spki_fingerprint == expected["spki_fingerprint"]
        assert actual.hostname_valid is expected["hostname_valid"]
        assert actual.trust_valid is expected["trust_valid"]
        categories = {finding["category"] for finding in actual.findings}
        assert set(expected["expected_findings"]) <= categories
    evaluation = evaluate_ground_truth(scan.results, str(generated_lab / "ground_truth.json"))
    assert evaluation["detectors"]["precision"] == 1
    assert evaluation["detectors"]["recall"] == 1
    assert evaluation["relationships"]["shared_certificates"]["precision"] == 1
    assert evaluation["relationships"]["shared_certificates"]["recall"] == 1
    assert evaluation["relationships"]["shared_spkis"]["precision"] == 1
    assert evaluation["relationships"]["shared_spkis"]["recall"] == 1


@pytest.mark.integration
def test_v1_v2_equivalent_findings(project_root, generated_lab, lab_running):
    config = load_config(str(project_root / "allowlist.yaml"))
    v1 = scan_sequential(config)
    v2 = asyncio.run(scan_async(config, 5))
    def categories(scan): return {r.target.name: {f["category"] for f in r.findings} for r in scan.results}
    assert categories(v1) == categories(v2)
    assert {r.target.name: r.certificate.certificate_fingerprint for r in v1.results} == {r.target.name: r.certificate.certificate_fingerprint for r in v2.results}
    assert v2.peak_concurrency <= 5
