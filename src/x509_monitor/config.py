import ipaddress
import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List

import yaml

from .models import Target


class UnsafeTargetError(ValueError):
    pass


@dataclass
class Config:
    path: Path
    targets: List[Target]
    ca_file: Path
    timeout_seconds: float
    concurrency: int
    expiry_warning_days: int
    weak_key_rules: Dict[str, int]
    weak_signature_hashes: List[str]
    allow_public_targets: bool


def _is_local_or_private(host: str) -> bool:
    if host.lower() == "localhost" or host.lower().endswith(".localhost"):
        return True
    try:
        addresses = [ipaddress.ip_address(host)]
    except ValueError:
        try:
            addresses = [ipaddress.ip_address(item[4][0]) for item in socket.getaddrinfo(host, None)]
        except socket.gaierror:
            return False
    return bool(addresses) and all(
        ip.is_private or ip.is_loopback or ip.is_link_local for ip in addresses
    )


def load_config(path: str) -> Config:
    config_path = Path(path).expanduser().resolve()
    if not config_path.is_file():
        raise ValueError(f"Explicit allowlist file does not exist: {config_path}")
    raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    if not raw.get("authorization_acknowledged", False):
        raise UnsafeTargetError("Set authorization_acknowledged: true after confirming authorization for every target")
    allow_public = bool(raw.get("allow_public_targets", False))
    targets = []
    for item in raw.get("targets", []):
        target = Target(
            name=str(item["name"]), host=str(item["host"]), port=int(item["port"]),
            server_name=str(item.get("server_name") or item["host"]),
        )
        if not (1 <= target.port <= 65535):
            raise ValueError(f"Invalid port for {target.name}: {target.port}")
        if not allow_public and not _is_local_or_private(target.host):
            raise UnsafeTargetError(
                f"Refusing non-local/private target {target.host}; explicit public-target opt-in is required"
            )
        targets.append(target)
    if not targets:
        raise ValueError("Allowlist must contain at least one explicit target; range discovery is unsupported")
    if len({t.identity for t in targets}) != len(targets):
        raise ValueError("Duplicate target identities are not allowed")
    ca_value = raw.get("ca_file", "lab/certs/ca/ca.pem")
    ca_file = (config_path.parent / ca_value).resolve() if not Path(ca_value).is_absolute() else Path(ca_value)
    timeout = float(raw.get("timeout_seconds", 3.0))
    concurrency = int(raw.get("concurrency", 5))
    if not (0.1 <= timeout <= 30):
        raise ValueError("timeout_seconds must be between 0.1 and 30")
    if not (1 <= concurrency <= 100):
        raise ValueError("concurrency must be between 1 and 100")
    return Config(
        path=config_path, targets=targets, ca_file=ca_file, timeout_seconds=timeout,
        concurrency=concurrency, expiry_warning_days=int(raw.get("expiry_warning_days", 30)),
        weak_key_rules={str(k): int(v) for k, v in raw.get("weak_key_rules", {}).items()},
        weak_signature_hashes=[str(v).lower() for v in raw.get("weak_signature_hashes", ["md5", "sha1"])],
        allow_public_targets=allow_public,
    )
