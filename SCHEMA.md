# Bundle schema v1

Bundles are standard ZIP archives. `manifest.json` has the CrashPack version, UTC creation time, application identity/version/optional commit, schema version, platform, collector records (permission, timeout, cap, sensitivity), redaction summary, and SHA-256 checksums for each collected entry. `redaction-report.json` contains only category counts. Content can be organized under `system/`, `application/`, `logs/`, `docker/`, `network/`, and `diagnostics/`. Archive member paths must be relative and traversal-free.
