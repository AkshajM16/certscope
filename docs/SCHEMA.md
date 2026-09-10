# SQLite schema and query semantics

Migration `sql/migrations/001_initial.sql` is applied by `x509-monitor init-db` or any command that opens the database. Applied integer versions are recorded in `schema_migrations`.

- `scans` is one immutable command run, with mode and configured/observed concurrency.
- `endpoints` normalizes stable `name@host:port` identities and retains the SNI/hostname expectation.
- `certificates` deduplicates parsed leaf certificates by full SHA-256 fingerprint and indexes SPKI SHA-256 for key clustering.
- `observations` joins exactly one endpoint to one scan and records transport, verification, timing, chain, and error state. `UNIQUE(scan_id, endpoint_id)` enforces idempotence within a snapshot.
- `findings` stores rule outputs per observation and deduplicates identical category/detail pairs.

Foreign keys are enabled for each connection. Scan deletion cascades to observations and findings, but certificates and endpoints remain normalized intelligence entities. Timestamps are timezone-aware ISO 8601 UTC strings. The schema stores SAN and chain arrays as JSON because SQLite has no native array type; query code decodes them before analysis.

Example relationship query:

```sql
SELECT spki_sha256, COUNT(DISTINCT fingerprint_sha256) AS certificates
FROM certificates
GROUP BY spki_sha256
HAVING COUNT(DISTINCT fingerprint_sha256) > 1;
```

Example endpoint history query:

```sql
SELECT s.id, s.started_at, o.certificate_fingerprint, o.error_class
FROM observations o
JOIN scans s ON s.id = o.scan_id
JOIN endpoints e ON e.id = o.endpoint_id
WHERE e.identity = 'valid@127.0.0.1:8443'
ORDER BY s.id;
```
