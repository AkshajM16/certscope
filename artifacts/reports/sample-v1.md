# X.509 scan 1

| Target            | Cert SHA-256       | SPKI SHA-256       | TLS     | Host   | Trust   | Findings           |   ms |
|-------------------|--------------------|--------------------|---------|--------|---------|--------------------|------|
| valid             | 3F:18:8D:3E:3F:0E… | 74:1C:6B:87:A4:B7… | TLSv1.3 | yes    | yes     | none               | 21.7 |
| expired           | 54:9A:A7:6D:D4:D8… | 36:9C:31:BD:3F:5B… | TLSv1.3 | yes    | no      | expired, untrusted |  8.3 |
| hostname-mismatch | 2F:BF:9F:77:4D:66… | 52:1B:AF:F1:AC:5D… | TLSv1.3 | no     | yes     | hostname_mismatch  |  7.7 |
| self-signed       | 6E:C9:EC:09:BC:8B… | FA:CE:5B:0D:AB:96… | TLSv1.3 | yes    | no      | untrusted          |  5.8 |
| shared-cert-a     | 33:2D:0B:BB:3F:5B… | A7:71:25:0A:9E:C4… | TLSv1.3 | yes    | yes     | none               |  4.8 |
| shared-cert-b     | 33:2D:0B:BB:3F:5B… | A7:71:25:0A:9E:C4… | TLSv1.3 | yes    | yes     | none               |  6.9 |
| shared-spki-a     | 8E:37:8D:D0:1F:F8… | 39:1D:1A:7D:B4:40… | TLSv1.3 | yes    | yes     | none               |  3.9 |
| shared-spki-b     | 15:8D:DB:91:7F:57… | 39:1D:1A:7D:B4:40… | TLSv1.3 | yes    | yes     | none               |  4   |

## Relationship view

- Identical certificate
  - `33:2D:0B:BB:3F:5B:C2:AE:FB:F3:91:5E:BB:9F:B0:95:4D:D0:E8:44:8B:88:F0:63:2D:26:37:4E:51:58:F7:89`
    - shared-cert-a
    - shared-cert-b
- Identical SPKI/key
  - `39:1D:1A:7D:B4:40:B5:64:B3:34:60:AB:D9:BF:C7:36:0B:91:10:2D:CF:14:14:16:BC:EE:78:31:44:D9:F0:DC`
    - shared-spki-a
    - shared-spki-b
  - `A7:71:25:0A:9E:C4:09:2B:BF:EE:96:1D:E6:72:F2:94:37:96:65:CF:09:46:18:B8:0B:0D:E4:50:07:F2:0A:A6`
    - shared-cert-a
    - shared-cert-b

Mode: `v1`; configured concurrency: 1; observed peak: 1.
