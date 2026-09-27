# Contributing

Run `cargo test` before proposing a change. New collectors must be explicit, bounded, local-only, and redact output before persistence. Add known-secret regression fixtures for redaction changes; a fixture secret must never remain in a generated bundle.
