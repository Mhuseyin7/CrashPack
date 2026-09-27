# Threat model

CrashPack treats configuration, application output, filenames, archives, and logs as untrusted.

| Threat | Control |
| --- | --- |
| Broad data collection | Only explicit relative file rules are permitted. |
| Path traversal / symlink escape | Canonical target must remain beneath the canonical config root. |
| Command injection | Executable and argv are separate; no shell mode exists. |
| Hung or huge commands | Timeouts, null stdin, and output caps. |
| Huge logs | Per-file cap; optional tail; global sanitized-content cap. |
| Secret leakage | Deterministic redaction before ZIP writing; no originals in report. |
| Zip slip on inspection | All entry names are validated before checksum verification. |
| Malicious binary logs | Lossy UTF-8 decoding produces bounded, safe output. |

Non-goals: endpoint scanning, telemetry, automatic uploads, hardware identifiers, full environment capture, and perfect detection of every secret or PII value.
