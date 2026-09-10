# Security policy and responsible use

This software is an inventory tool, not a target-discovery scanner. Use it only for hosts you own or have explicit permission to assess.

Safe defaults require an explicit allowlist, a positive authorization acknowledgement, local/private destinations, short timeouts, and bounded concurrency. Public destinations require a deliberate configuration opt-in and remain the operator's responsibility. The project never expands ranges, follows redirects, evades defenses, or sends application data beyond TLS handshakes.

Generated lab private keys are disposable. They are excluded from version control and copied only into local Docker images. Do not report those fixtures as leaked production secrets. For a security flaw in the monitor itself, disclose it privately to the repository owner with reproduction steps that use the local lab.
