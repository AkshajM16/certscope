VENVDIR ?= $(HOME)/.cache/x509-exposure-monitor-venv

.PHONY: install lab-generate lab-start lab-stop scan-v1 scan-v2 diff test benchmark plots package

install:
	python3 -m venv $(VENVDIR)
	ln -sfn $(VENVDIR) .venv
	.venv/bin/pip install -r requirements-dev.txt
	.venv/bin/pip install -e .

lab-generate:
	.venv/bin/x509-monitor lab generate

lab-start:
	.venv/bin/x509-monitor lab start

lab-stop:
	.venv/bin/x509-monitor lab stop

scan-v1:
	.venv/bin/x509-monitor scan --mode v1

scan-v2:
	.venv/bin/x509-monitor scan --mode v2

diff:
	.venv/bin/x509-monitor diff

test:
	@set -eu; trap 'docker compose down' EXIT INT TERM; \
		.venv/bin/x509-monitor lab start; \
		.venv/bin/pytest

benchmark:
	@set -eu; trap 'docker compose down' EXIT INT TERM; \
		.venv/bin/x509-monitor lab start; \
		.venv/bin/x509-monitor benchmark

plots:
	.venv/bin/x509-monitor plot $$(ls -t artifacts/benchmarks/*.json | head -1)

package:
	.venv/bin/python -m build
