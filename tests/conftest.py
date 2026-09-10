import socket
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="session")
def project_root():
    return ROOT


@pytest.fixture(scope="session")
def generated_lab(project_root):
    manifest = project_root / "lab" / "certs" / "ground_truth.json"
    if not manifest.exists():
        subprocess.run([sys.executable, str(project_root / "lab" / "generate_certs.py")], check=True)
    return project_root / "lab" / "certs"


@pytest.fixture(scope="session")
def lab_running(generated_lab):
    try:
        with socket.create_connection(("127.0.0.1", 8443), timeout=0.2):
            return True
    except OSError:
        pytest.skip("Docker Compose TLS lab is not running")
