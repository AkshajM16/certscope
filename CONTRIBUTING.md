# Contributing

Contributions are welcome for the local, authorization-first use cases described in the README. Do not add target discovery, address-range expansion, stealth, evasion, credential attacks, or default public-Internet targets.

## Development setup

```bash
make install
make lab-generate
make test
make package
```

`make test` starts the disposable Docker Compose lab and always runs `docker compose down` when testing finishes or fails. It preserves volumes and does not stop Docker Desktop or the global Docker engine.

Before opening a pull request:

1. Add or update tests for behavior changes.
2. Keep the explicit allowlist and authorization acknowledgement mandatory.
3. Confirm that no generated private keys, databases, credentials, caches, or virtual environments are staged.
4. Run the full test suite and package build.
5. Document benchmark scope and raw data for performance claims.

Generated lab keys are disposable fixtures and must never be committed. Reports may contain certificate subjects or SANs; sanitize reports from non-lab environments before sharing them.
