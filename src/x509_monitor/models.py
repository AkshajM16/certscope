from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class Target:
    name: str
    host: str
    port: int
    server_name: str

    @property
    def identity(self) -> str:
        return f"{self.name}@{self.host}:{self.port}"


@dataclass
class CertificateMetadata:
    subject: str
    issuer: str
    sans: List[str]
    serial: str
    not_before: str
    not_after: str
    signature_algorithm: str
    signature_hash: Optional[str]
    public_key_algorithm: str
    public_key_size: Optional[int]
    certificate_fingerprint: str
    spki_fingerprint: str
    pem: str


@dataclass
class ProbeResult:
    target: Target
    collected_at: str
    latency_ms: float
    certificate: Optional[CertificateMetadata] = None
    chain_fingerprints: List[str] = field(default_factory=list)
    tls_version: Optional[str] = None
    cipher: Optional[str] = None
    hostname_valid: Optional[bool] = None
    trust_valid: Optional[bool] = None
    verification_error: Optional[str] = None
    error_class: Optional[str] = None
    error_message: Optional[str] = None
    findings: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    mode: str
    started_at: str
    completed_at: str
    configured_concurrency: int
    peak_concurrency: int
    results: List[ProbeResult]
    scan_id: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
