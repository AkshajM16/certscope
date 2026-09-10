import asyncio
import socket
import ssl
import time
from datetime import datetime, timezone
from typing import List, Tuple

from .analyzer import analyze
from .certificates import extract_chain_fingerprints, hostname_matches, parse_certificate
from .config import Config
from .models import ProbeResult, ScanResult, Target


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def unverified_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def trust_context(ca_file: str) -> ssl.SSLContext:
    context = ssl.create_default_context(cafile=ca_file)
    context.check_hostname = False
    return context


def classify_error(exc: BaseException) -> str:
    if isinstance(exc, (TimeoutError, socket.timeout, asyncio.TimeoutError)):
        return "timeout"
    if isinstance(exc, socket.gaierror):
        return "dns_error"
    if isinstance(exc, ConnectionRefusedError):
        return "connection_refused"
    if isinstance(exc, ssl.SSLCertVerificationError):
        return "certificate_verification_error"
    if isinstance(exc, ssl.SSLError):
        return "tls_handshake_error"
    if isinstance(exc, asyncio.CancelledError):
        return "cancelled"
    if isinstance(exc, OSError):
        return "network_error"
    return "internal_error"


def _verify_sync(target: Target, config: Config) -> Tuple[bool, str]:
    try:
        with socket.create_connection((target.host, target.port), timeout=config.timeout_seconds) as raw:
            with trust_context(str(config.ca_file)).wrap_socket(raw, server_hostname=target.server_name):
                return True, None
    except Exception as exc:
        return False, f"{classify_error(exc)}: {exc}"


def probe_sync(target: Target, config: Config) -> ProbeResult:
    started = time.perf_counter()
    result = ProbeResult(target=target, collected_at=utc_now(), latency_ms=0.0)
    try:
        with socket.create_connection((target.host, target.port), timeout=config.timeout_seconds) as raw:
            raw.settimeout(config.timeout_seconds)
            with unverified_context().wrap_socket(raw, server_hostname=target.server_name) as tls:
                der = tls.getpeercert(binary_form=True)
                result.certificate = parse_certificate(der)
                result.chain_fingerprints = extract_chain_fingerprints(tls)
                result.tls_version = tls.version()
                result.cipher = tls.cipher()[0] if tls.cipher() else None
        result.hostname_valid = hostname_matches(result.certificate.sans, target.server_name)
        result.trust_valid, result.verification_error = _verify_sync(target, config)
    except BaseException as exc:
        result.error_class = classify_error(exc)
        result.error_message = str(exc)
    result.latency_ms = (time.perf_counter() - started) * 1000
    result.findings = analyze(result, config)
    return result


def scan_sequential(config: Config) -> ScanResult:
    started = utc_now()
    results = [probe_sync(target, config) for target in config.targets]
    return ScanResult("v1", started, utc_now(), 1, 1 if results else 0, results)


class ConcurrencyTracker:
    def __init__(self):
        self.active = 0
        self.peak = 0
        self._lock = asyncio.Lock()

    async def enter(self):
        async with self._lock:
            self.active += 1
            self.peak = max(self.peak, self.active)

    async def exit(self):
        async with self._lock:
            self.active -= 1


async def _verify_async(target: Target, config: Config) -> Tuple[bool, str]:
    writer = None
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(target.host, target.port, ssl=trust_context(str(config.ca_file)), server_hostname=target.server_name),
            timeout=config.timeout_seconds,
        )
        return True, None
    except Exception as exc:
        return False, f"{classify_error(exc)}: {exc}"
    finally:
        if writer:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


async def probe_async(target: Target, config: Config) -> ProbeResult:
    started = time.perf_counter()
    result = ProbeResult(target=target, collected_at=utc_now(), latency_ms=0.0)
    writer = None
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(target.host, target.port, ssl=unverified_context(), server_hostname=target.server_name),
            timeout=config.timeout_seconds,
        )
        tls_object = writer.get_extra_info("ssl_object")
        der = tls_object.getpeercert(binary_form=True)
        result.certificate = parse_certificate(der)
        result.chain_fingerprints = extract_chain_fingerprints(tls_object)
        result.tls_version = tls_object.version()
        result.cipher = tls_object.cipher()[0] if tls_object.cipher() else None
        result.hostname_valid = hostname_matches(result.certificate.sans, target.server_name)
        result.trust_valid, result.verification_error = await _verify_async(target, config)
    except BaseException as exc:
        result.error_class = classify_error(exc)
        result.error_message = str(exc)
        if isinstance(exc, asyncio.CancelledError):
            raise
    finally:
        if writer:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
    result.latency_ms = (time.perf_counter() - started) * 1000
    result.findings = analyze(result, config)
    return result


async def scan_async(config: Config, concurrency: int = None) -> ScanResult:
    limit = concurrency or config.concurrency
    semaphore = asyncio.Semaphore(limit)
    tracker = ConcurrencyTracker()
    started = utc_now()

    async def bounded(target):
        async with semaphore:
            await tracker.enter()
            try:
                return await probe_async(target, config)
            finally:
                await tracker.exit()

    tasks = [asyncio.create_task(bounded(target), name=f"probe:{target.identity}") for target in config.targets]
    try:
        results = await asyncio.gather(*tasks)
    except BaseException:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        raise
    return ScanResult("v2", started, utc_now(), limit, tracker.peak, results)
