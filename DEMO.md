# Five-minute certificate rotation demo

Only run this against the included loopback lab or endpoints you are authorized to assess.

```bash
make install
make lab-generate
make lab-start

# Baseline inventory; note the printed scan ID.
.venv/bin/x509-monitor scan --mode v2 --concurrency 5 --markdown artifacts/reports/generated-baseline.md

# Generate a new certificate and key, rebuild only `valid`, and wait until ready.
.venv/bin/x509-monitor lab rotate --target valid

# Capture a second immutable snapshot; note its scan ID.
.venv/bin/x509-monitor scan --mode v2 --concurrency 5 --markdown artifacts/reports/generated-rotated.md

# Replace IDs with the two values printed above.
.venv/bin/x509-monitor diff --previous 1 --current 2 --json artifacts/reports/generated-diff.json
```

Expected core changes:

```text
valid@127.0.0.1:8443  certificate_rotation  leaf fingerprint changed
valid@127.0.0.1:8443  key_rotation          SPKI fingerprint changed
```

To demonstrate certificate renewal while retaining the key, repeat with `--reuse-key`; the diff reports `certificate_rotation` plus `key_reuse`. The expired lab endpoint also appears as `impending_expiry` because an already-expired certificate is inside every warning horizon.

Finish with `.venv/bin/x509-monitor lab stop`.
