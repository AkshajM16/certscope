from pathlib import Path

import pytest

from x509_monitor.config import UnsafeTargetError, load_config


def test_explicit_allowlist_and_authorization_required(tmp_path):
    path = tmp_path / "allowlist.yaml"
    path.write_text("targets: [{name: local, host: 127.0.0.1, port: 443}]\n")
    with pytest.raises(UnsafeTargetError): load_config(str(path))


def test_public_target_rejected_without_opt_in(tmp_path, monkeypatch):
    path = tmp_path / "allowlist.yaml"
    path.write_text("authorization_acknowledged: true\ntargets: [{name: public, host: 8.8.8.8, port: 443}]\n")
    with pytest.raises(UnsafeTargetError): load_config(str(path))


def test_no_range_discovery_syntax(tmp_path):
    path = tmp_path / "allowlist.yaml"
    path.write_text("authorization_acknowledged: true\ntargets: [{name: range, host: 127.0.0.0/24, port: 443}]\n")
    with pytest.raises(UnsafeTargetError): load_config(str(path))
