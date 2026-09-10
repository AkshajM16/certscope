import asyncio
import socket
import socketserver
import threading

import pytest

from x509_monitor.config import load_config
from x509_monitor.models import Target
from x509_monitor.scanner import classify_error, probe_sync, scan_async


def test_error_classification():
    assert classify_error(socket.timeout()) == "timeout"
    assert classify_error(ConnectionRefusedError()) == "connection_refused"
    assert classify_error(socket.gaierror()) == "dns_error"


def test_unreachable_target_returns_classified_error(project_root):
    config = load_config(str(project_root / "allowlist.yaml"))
    config.targets = [Target("unreachable", "127.0.0.1", 1, "unreachable.local")]
    config.timeout_seconds = 0.2
    result = probe_sync(config.targets[0], config)
    assert result.error_class in {"connection_refused", "network_error", "timeout"}
    assert result.findings[0]["category"] == "connection_failure"


def test_malformed_tls_is_classified_without_hanging(project_root):
    class Plaintext(socketserver.BaseRequestHandler):
        def handle(self): self.request.sendall(b"this is not TLS\n")
    with socketserver.TCPServer(("127.0.0.1", 0), Plaintext) as server:
        thread = threading.Thread(target=server.handle_request, daemon=True); thread.start()
        config = load_config(str(project_root / "allowlist.yaml")); config.timeout_seconds = 0.5
        target = Target("malformed", "127.0.0.1", server.server_address[1], "malformed.local")
        result = probe_sync(target, config); thread.join(timeout=1)
    assert result.error_class == "tls_handshake_error"


@pytest.mark.asyncio
async def test_cancellation_cleans_all_probe_tasks(project_root, monkeypatch):
    config = load_config(str(project_root / "allowlist.yaml"))
    entered = asyncio.Event()

    async def never_finishes(target, config):
        entered.set()
        await asyncio.Future()

    monkeypatch.setattr("x509_monitor.scanner.probe_async", never_finishes)
    parent = asyncio.create_task(scan_async(config, 2))
    await entered.wait()
    parent.cancel()
    with pytest.raises(asyncio.CancelledError): await parent
    await asyncio.sleep(0)
    assert not [task for task in asyncio.all_tasks() if task is not asyncio.current_task() and task.get_name().startswith("probe:")]
