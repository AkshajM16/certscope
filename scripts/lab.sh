#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
python -m lab.generate_certs
docker compose up -d --build
