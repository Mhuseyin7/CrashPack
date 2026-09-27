# CrashPack

> Local-first, privacy-preserving diagnostic support bundle CLI.

CrashPack, bir application kullanıcısının cihazında oluşan ancak geliştiricinin kendi ortamında reproduce edemediği problemler için güvenli diagnostic bundle üretir. Logs, system metadata ve açıkça tanımlanan diagnostics kaynaklarını tek bir portable ZIP bundle içinde toplar; paylaşılmadan önce secrets ve kişisel veriler için deterministic redaction uygular.

Bu proje açık kaynak kodludur ve [muhammedkoca.com.tr](https://muhammedkoca.com.tr) tarafından geliştirilmiştir.

## Neden CrashPack?

Production incidents sırasında ihtiyaç duyulan bilgi genellikle kullanıcının device'ında bulunur. Ancak raw logs göndermek; API keys, authorization headers, session tokens, e-mail adresleri veya IP addresses gibi hassas bilgileri sızdırabilir.

CrashPack bu problemi privacy-first bir yaklaşımla çözer:

- **Local by default:** Data hiçbir zaman otomatik upload edilmez veya cloud service'e gönderilmez.
- **Explicit collection:** Sadece `crashpack.yml` içinde açıkça izin verilen kaynaklar okunur.
- **Secure redaction:** Tokens, credentials, JWTs, private keys, e-mails, IP addresses ve sensitive URL query values bundle'a yazılmadan önce temizlenir.
- **Portable bundles:** Standard ZIP format, SHA-256 checksums ve inspect/verify workflow.
- **User control:** `preview` ile collection planını görün; bundle'ı paylaşmadan önce local olarak inspect edin.

## Quick Start

Rust toolchain kuruluysa:

```powershell
git clone https://github.com/Mhuseyin7/CrashPack.git
cd CrashPack
cargo run -- init
```

Bu işlem conservative bir `crashpack.yml` oluşturur. File paths ve commands eklemeden önce mutlaka gözden geçirin.

```powershell
# Hiçbir şey toplamadan önce planı inceleyin
cargo run -- preview

# Sanitized local support bundle oluşturun
cargo run -- collect

# Bundle manifest'ini güvenli biçimde görüntüleyin
cargo run -- inspect .\crashpack-YYYY-MM-DD-HHMMSS.zip

# Entry checksums doğrulayın
cargo run -- verify .\crashpack-YYYY-MM-DD-HHMMSS.zip
```

CrashPack oluşturduğu bundle'ı yalnızca local disk'e yazar. Upload veya telemetry capability içermez.

## Example Configuration

```yaml
version: 1

application:
  name: ExampleApp
  version: 1.2.3
  commit: abc1234

collect:
  system: true
  runtime: true

  # Only explicit project-relative files or project-contained globs.
  files:
    - path: logs/*.log
      max_bytes: 5000000
      tail: true

  # Executable and argv are separate. Shell strings are not supported.
  commands:
    - name: app-version
      executable: example-app
      args: [--version]

  # Docker inspect and container environment variables are never collected.
  docker: false

  # Names are safe metadata. Values require an explicit allowlist.
  environment:
    names: [APP_ENV]
    values_allowlist: []

  # Explicit endpoint checks only; no network scanning.
  network:
    endpoints:
      - name: api
        host: api.example.com
        port: 443

  application_metadata:
    build_mode: release
    feature_flags: payments-v2

redaction:
  privacy_level: STRICT
  emails: true
  ip_addresses: true
  paths: true
  custom_patterns: []

limits:
  max_bundle_bytes: 52428800
  command_timeout_secs: 10
```

## Included Collectors

| Collector | Collected data | Safety boundary |
| --- | --- | --- |
| System | OS, kernel, architecture, CPU count, memory, uptime | No serial number or hardware identifier |
| Runtime | Node.js, Python, PHP, Java, Go, Rust versions | Fixed `--version` argv only |
| Files | Configured files and project-contained globs | Relative paths, symlink escape protection, byte cap, optional tail |
| Commands | Configured diagnostic command output | No shell, null stdin, timeout and output cap |
| Docker | Version and container name/image/status | No `inspect`, environment variables or secrets |
| Environment | Configured variable names; explicitly allowed values | Never captures the complete environment |
| Network | DNS resolution and one TCP reachability check | Explicit endpoints only; no scanning |
| Application | Configured build/feature/plugin metadata | No user content by default |

## Redaction

CrashPack uses deterministic, testable rules. It detects and replaces:

- Authorization headers and bearer tokens
- JWTs, API keys, session tokens, passwords and cookies
- AWS-style access key identifiers
- PEM private-key blocks
- Sensitive query values in URLs
- E-mail addresses, IPv4/IPv6 addresses and user-home paths
- Project-specific custom regex patterns

Repeated values receive stable placeholders inside the same bundle, preserving useful correlation without exposing the original value. `redaction-report.json` includes only category counts; redacted source values are never stored.

No automated detector can guarantee that all secrets or PII have been removed. Always use `preview`, then inspect the resulting bundle before sharing it externally.

## CLI Reference

```text
crashpack init [config]                 Create a conservative starter config
crashpack preview --config <file>       Display the collection plan only
crashpack collect --config <file>       Create a sanitized ZIP bundle
crashpack inspect <bundle.zip>          Print manifest without unsafe extraction
crashpack verify <bundle.zip>           Validate paths and SHA-256 checksums
crashpack doctor --config <file>        Validate config and local tool availability
crashpack redact <file>                 Write sanitized content to stdout
```

## Security & Privacy

CrashPack is intentionally **not** spyware, remote monitoring, crash-report telemetry, a raw log dumper or an automatic cloud-upload utility. It does not scan the entire machine, execute raw shell strings, collect all environment values, send data to AI services, or hide what was collected.

Please read:

- [Threat Model](THREAT_MODEL.md)
- [Privacy Policy](PRIVACY.md)
- [Security Policy](SECURITY.md)
- [Bundle Schema](SCHEMA.md)
- [Exit Codes](EXIT_CODES.md)

## Development

```powershell
cargo fmt --check
cargo test
```

CI runs formatting, unit tests and a known-secret bundle regression test. The build fails if the fixture's known secrets appear in the resulting ZIP.

Contributions are welcome. Before submitting a change, read [CONTRIBUTING.md](CONTRIBUTING.md) and keep the local-first, explicit-consent security model intact.

## License

Licensed under [Apache-2.0](LICENSE).

---

Developed by [muhammedkoca.com.tr](https://muhammedkoca.com.tr) · Open source diagnostic tooling built with privacy and trust as first-class requirements.
