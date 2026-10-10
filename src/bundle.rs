use crate::{
    config::Config,
    redact::{Engine, Summary},
};
use anyhow::{bail, Context, Result};
use chrono::Utc;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{Read, Seek, SeekFrom, Write},
    net::{TcpStream, ToSocketAddrs},
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};
use sysinfo::{Disks, System};
use zip::{write::SimpleFileOptions, CompressionMethod, ZipArchive, ZipWriter};

#[derive(Serialize)]
struct Manifest {
    crashpack_version: &'static str,
    created_at: String,
    application: String,
    application_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    application_commit: Option<String>,
    bundle_schema_version: u8,
    platform: Platform,
    collectors: Vec<CollectorRecord>,
    redaction_summary: Summary,
    checksums: BTreeMap<String, String>,
}
#[derive(Serialize)]
struct CollectorRecord {
    name: String,
    permission: &'static str,
    timeout_secs: u64,
    max_output_bytes: u64,
    sensitivity: &'static str,
}
#[derive(Serialize)]
struct Platform {
    os: String,
    architecture: String,
}
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn safe_archive_path(name: &str) -> bool {
    if name.is_empty() || name.contains(['\\', '\0']) {
        return false;
    }
    let p = Path::new(name);
    !p.is_absolute()
        && !p.components().any(|c| {
            matches!(
                c,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
}
fn approved_path(root: &Path, configured: &str) -> Result<PathBuf> {
    let candidate = root.join(configured);
    let canonical_root = root.canonicalize()?;
    let canonical = candidate
        .canonicalize()
        .with_context(|| format!("cannot access configured file {configured}"))?;
    if !canonical.starts_with(&canonical_root) {
        bail!("configured path escapes project root: {configured}")
    }
    if !canonical.is_file() {
        bail!("configured path is not a file: {configured}")
    }
    Ok(canonical)
}
fn approved_paths(root: &Path, configured: &str) -> Result<Vec<PathBuf>> {
    if !configured.contains(['*', '?', '[']) {
        return Ok(vec![approved_path(root, configured)?]);
    }
    let pattern = root.join(configured).to_string_lossy().into_owned();
    let canonical_root = root.canonicalize()?;
    let mut matches = Vec::new();
    for candidate in glob::glob(&pattern).context("invalid file glob")? {
        let canonical = candidate?.canonicalize()?;
        if !canonical.starts_with(&canonical_root) {
            bail!("glob matched a path outside the project root")
        }
        if canonical.is_file() {
            matches.push(canonical);
        }
    }
    if matches.is_empty() {
        bail!("configured file glob matched no files: {configured}")
    }
    Ok(matches)
}
fn read_limited(path: &Path, max: u64, tail: bool) -> Result<Vec<u8>> {
    let mut f = File::open(path)?;
    let length = f.metadata()?.len();
    if tail && length > max {
        f.seek(SeekFrom::End(-(max as i64)))?;
    }
    let mut out = Vec::new();
    f.take(max).read_to_end(&mut out)?;
    Ok(out)
}
fn command_output(executable: &str, args: &[String], max: u64, seconds: u64) -> Result<Vec<u8>> {
    let mut child = Command::new(executable)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("cannot start command {executable}"))?;
    let deadline = std::time::Instant::now() + Duration::from_secs(seconds);
    loop {
        if child.try_wait()?.is_some() {
            let out = child.wait_with_output()?;
            let mut data = out.stdout;
            data.extend_from_slice(&out.stderr);
            data.truncate(max as usize);
            return Ok(data);
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            bail!("command {executable} timed out after {seconds}s")
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}
fn system_info() -> String {
    let mut s = System::new_all();
    s.refresh_all();
    let disks = Disks::new_with_refreshed_list();
    let total_disk_bytes: u64 = disks.iter().map(|disk| disk.total_space()).sum();
    let available_disk_bytes: u64 = disks.iter().map(|disk| disk.available_space()).sum();
    format!("os: {}\nkernel: {}\narchitecture: {}\ncpu_count: {}\ntotal_memory_bytes: {}\navailable_memory_bytes: {}\ntotal_disk_bytes: {}\navailable_disk_bytes: {}\nuptime_seconds: {}\n", System::name().unwrap_or_else(|| "unknown".into()), System::kernel_version().unwrap_or_else(|| "unknown".into()), std::env::consts::ARCH, s.cpus().len(), s.total_memory(), s.available_memory(), total_disk_bytes, available_disk_bytes, System::uptime())
}
fn collector(
    name: impl Into<String>,
    permission: &'static str,
    timeout_secs: u64,
    max_output_bytes: u64,
    sensitivity: &'static str,
) -> CollectorRecord {
    CollectorRecord {
        name: name.into(),
        permission,
        timeout_secs,
        max_output_bytes,
        sensitivity,
    }
}
fn network_probe(host: &str, port: u16, timeout: Duration) -> Result<String> {
    let addresses: Vec<_> = (host, port)
        .to_socket_addrs()
        .with_context(|| format!("DNS resolution failed for {host}"))?
        .collect();
    if addresses.is_empty() {
        bail!("DNS returned no addresses for {host}")
    }
    let started = std::time::Instant::now();
    let mut result = format!(
        "host: {host}\nport: {port}\ndns_addresses: {}\n",
        addresses
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    );
    match TcpStream::connect_timeout(&addresses[0], timeout) {
        Ok(_) => result.push_str(&format!(
            "tcp_reachable: true\nlatency_ms: {}\n",
            started.elapsed().as_millis()
        )),
        Err(e) => result.push_str(&format!("tcp_reachable: false\nerror: {}\n", e.kind())),
    }
    Ok(result)
}

pub fn preview(cfg: &Config, root: &Path) -> Result<()> {
    println!("CrashPack preview (nothing is collected or uploaded)\n");
    let mut n = 0;
    if cfg.collect.system {
        println!("✓ system metadata (non-identifier fields)");
        n += 1;
    }
    if cfg.collect.runtime {
        println!("✓ configured runtime versions");
        n += 1;
    }
    if cfg.collect.docker {
        println!("✓ Docker version and container name/image/status (no inspect or env)");
        n += 1;
    }
    if !cfg.collect.application_metadata.is_empty() {
        println!(
            "✓ {} application metadata field(s)",
            cfg.collect.application_metadata.len()
        );
        n += 1;
    }
    if !cfg.collect.environment.names.is_empty()
        || !cfg.collect.environment.values_allowlist.is_empty()
    {
        println!(
            "✓ {} environment name(s); {} explicitly allowed value(s)",
            cfg.collect.environment.names.len(),
            cfg.collect.environment.values_allowlist.len()
        );
        n += 1;
    }
    for endpoint in &cfg.collect.network.endpoints {
        println!(
            "✓ network {}: {}:{} (DNS + one TCP connection)",
            endpoint.name, endpoint.host, endpoint.port
        );
        n += 1;
    }
    for f in &cfg.collect.files {
        let paths = approved_paths(root, &f.path)?;
        println!(
            "✓ {} ({} file(s), max {} bytes{})",
            f.path,
            paths.len(),
            f.max_bytes,
            if f.tail { ", tail" } else { "" }
        );
        n += paths.len();
    }
    for c in &cfg.collect.commands {
        println!(
            "✓ command {}: {} {:?} (no shell)",
            c.name, c.executable, c.args
        );
        n += 1;
    }
    println!("\nFiles/collectors: {n}\nGlobal limit: {} bytes\nRedaction: deterministic secrets, tokens, private keys{}{}", cfg.limits.max_bundle_bytes, if cfg.redaction.emails { ", emails" } else { "" }, if cfg.redaction.ip_addresses { ", IP addresses" } else { "" });
    Ok(())
}
pub fn doctor(cfg: &Config) {
    println!("✓ Configuration is valid");
    println!("✓ Local-only operation; no upload integration exists");
    for c in &cfg.collect.commands {
        println!(
            "{} {}",
            if Command::new(&c.executable)
                .arg("--version")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok()
            {
                "✓"
            } else {
                "!"
            },
            c.executable
        );
    }
    if cfg.collect.docker {
        println!(
            "{} docker",
            if Command::new("docker")
                .arg("version")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok()
            {
                "✓"
            } else {
                "!"
            }
        );
    }
}
pub fn collect(cfg: &Config, root: &Path, output: &Path) -> Result<PathBuf> {
    println!("Collecting diagnostics...");
    let mut entries: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut names = vec![];
    if cfg.collect.system {
        entries.insert("system/metadata.txt".into(), system_info().into_bytes());
        names.push(collector(
            "system",
            "local non-identifier OS metadata",
            0,
            100_000,
            "standard",
        ));
        println!("✓ System metadata");
    }
    if cfg.collect.runtime {
        for runtime in ["node", "python", "php", "java", "go", "rustc"] {
            if let Ok(data) = command_output(
                runtime,
                &["--version".into()],
                10_000,
                cfg.limits.command_timeout_secs,
            ) {
                entries.insert(format!("diagnostics/runtime-{runtime}.txt"), data);
            }
        }
        names.push(collector(
            "runtime",
            "execute fixed runtime --version argv",
            cfg.limits.command_timeout_secs,
            10_000,
            "standard",
        ));
        println!("✓ Runtime versions");
    }
    if !cfg.collect.application_metadata.is_empty() {
        entries.insert(
            "application/metadata.json".into(),
            serde_json::to_vec_pretty(&cfg.collect.application_metadata)?,
        );
        names.push(collector(
            "application_metadata",
            "configured metadata only",
            0,
            100_000,
            "standard",
        ));
        println!("✓ Application metadata");
    }
    if !cfg.collect.environment.names.is_empty()
        || !cfg.collect.environment.values_allowlist.is_empty()
    {
        let allowed: std::collections::BTreeSet<_> =
            cfg.collect.environment.values_allowlist.iter().collect();
        let mut data = std::collections::BTreeMap::new();
        for name in cfg
            .collect
            .environment
            .names
            .iter()
            .chain(cfg.collect.environment.values_allowlist.iter())
        {
            data.insert(
                name,
                if allowed.contains(name) {
                    std::env::var(name).ok()
                } else {
                    None
                },
            );
        }
        entries.insert(
            "application/environment.json".into(),
            serde_json::to_vec_pretty(&data)?,
        );
        names.push(collector(
            "environment_metadata",
            "configured environment names; values require allowlist",
            0,
            100_000,
            "sensitive",
        ));
        println!("✓ Environment metadata");
    }
    if cfg.collect.docker {
        let version = command_output(
            "docker",
            &["version".into(), "--format".into(), "{{json .}}".into()],
            100_000,
            cfg.limits.command_timeout_secs,
        )?;
        let containers = command_output(
            "docker",
            &[
                "ps".into(),
                "--format".into(),
                "{{.Names}}\t{{.Image}}\t{{.Status}}".into(),
            ],
            100_000,
            cfg.limits.command_timeout_secs,
        )?;
        entries.insert("docker/version.json".into(), version);
        entries.insert("docker/containers.txt".into(), containers);
        names.push(collector(
            "docker",
            "execute fixed docker metadata argv; excludes inspect/env",
            cfg.limits.command_timeout_secs,
            200_000,
            "standard",
        ));
        println!("✓ Docker metadata");
    }
    for endpoint in &cfg.collect.network.endpoints {
        let output = network_probe(
            &endpoint.host,
            endpoint.port,
            Duration::from_secs(cfg.limits.command_timeout_secs),
        )?;
        entries.insert(
            format!(
                "network/{}.txt",
                endpoint.name.replace(
                    |c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_',
                    "_"
                )
            ),
            output.into_bytes(),
        );
        names.push(collector(
            format!("network:{}", endpoint.name),
            "configured DNS/TCP endpoint only",
            cfg.limits.command_timeout_secs,
            10_000,
            "sensitive",
        ));
        println!("✓ Network: {}", endpoint.name);
    }
    let canonical_root = root.canonicalize()?;
    for rule in &cfg.collect.files {
        for p in approved_paths(root, &rule.path)? {
            let bytes = read_limited(&p, rule.max_bytes, rule.tail)?;
            let rel = p
                .strip_prefix(&canonical_root)
                .unwrap_or(&p)
                .to_string_lossy()
                .replace('\\', "/");
            entries.insert(format!("logs/{rel}"), bytes);
            println!("✓ {rel}");
            names.push(collector(
                format!("file:{rel}"),
                "explicit configured project-relative file or project-contained glob",
                0,
                rule.max_bytes,
                "sensitive",
            ));
        }
    }
    for rule in &cfg.collect.commands {
        let out = command_output(
            &rule.executable,
            &rule.args,
            rule.max_bytes,
            cfg.limits.command_timeout_secs,
        )?;
        entries.insert(
            format!(
                "diagnostics/{}.txt",
                rule.name.replace(
                    |c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_',
                    "_"
                )
            ),
            out,
        );
        println!("✓ Command: {}", rule.name);
        names.push(collector(
            format!("command:{}", rule.name),
            "configured executable + argv; no shell",
            cfg.limits.command_timeout_secs,
            rule.max_bytes,
            "sensitive",
        ));
    }
    println!("Sanitizing...");
    let mut engine = Engine::new(&cfg.redaction);
    let mut total = 0u64;
    for data in entries.values_mut() {
        *data = engine.sanitize(data);
        total += data.len() as u64;
        if total > cfg.limits.max_bundle_bytes {
            bail!("sanitized content exceeded max_bundle_bytes; no bundle created")
        }
    }
    let summary = engine.summary().clone();
    println!("✓ {} redactions applied", summary.total());
    let report = serde_json::to_vec_pretty(&engine.summary())?;
    entries.insert("redaction-report.json".into(), report);
    let mut checksums = BTreeMap::new();
    for (name, data) in &entries {
        checksums.insert(name.clone(), hash(data));
    }
    let manifest = Manifest {
        crashpack_version: env!("CARGO_PKG_VERSION"),
        created_at: Utc::now().to_rfc3339(),
        application: cfg.application.name.clone(),
        application_version: cfg.application.version.clone(),
        application_commit: cfg.application.commit.clone(),
        bundle_schema_version: 1,
        platform: Platform {
            os: std::env::consts::OS.into(),
            architecture: std::env::consts::ARCH.into(),
        },
        collectors: names,
        redaction_summary: summary,
        checksums,
    };
    let mbytes = serde_json::to_vec_pretty(&manifest)?;
    entries.insert("manifest.json".into(), mbytes);
    fs::create_dir_all(output)?;
    let file = output.join(format!(
        "crashpack-{}.zip",
        Utc::now().format("%Y-%m-%d-%H%M%S")
    ));
    let f = File::create(&file)?;
    let mut zip = ZipWriter::new(f);
    let opt = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
    for (name, data) in entries {
        zip.start_file(name, opt)?;
        zip.write_all(&data)?;
    }
    zip.finish()?;
    if fs::metadata(&file)?.len() > cfg.limits.max_bundle_bytes {
        fs::remove_file(&file)?;
        bail!("final ZIP exceeded max_bundle_bytes; no bundle was retained")
    }
    Ok(file)
}
pub fn inspect(path: &Path) -> Result<()> {
    let f = File::open(path)?;
    let mut zip = ZipArchive::new(f)?;
    for index in 0..zip.len() {
        if !safe_archive_path(zip.by_index(index)?.name()) {
            bail!("unsafe archive path")
        }
    }
    let mut m = String::new();
    zip.by_name("manifest.json")
        .context("bundle has no manifest.json")?
        .read_to_string(&mut m)?;
    let _: serde_json::Value = serde_json::from_str(&m)?;
    println!("{m}");
    Ok(())
}
pub fn verify(path: &Path) -> Result<()> {
    let f = File::open(path)?;
    let mut zip = ZipArchive::new(f)?;
    for i in 0..zip.len() {
        if !safe_archive_path(zip.by_index(i)?.name()) {
            bail!("unsafe archive path")
        }
    }
    let mut m = String::new();
    zip.by_name("manifest.json")?.read_to_string(&mut m)?;
    let manifest: serde_json::Value = serde_json::from_str(&m)?;
    let sums = manifest["checksums"]
        .as_object()
        .context("manifest checksums missing")?;
    for (name, want) in sums {
        let mut data = Vec::new();
        zip.by_name(name)?.read_to_end(&mut data)?;
        if want.as_str() != Some(&hash(&data)) {
            bail!("checksum mismatch for {name}")
        }
    }
    let listed: std::collections::BTreeSet<_> = sums.keys().map(String::as_str).collect();
    for index in 0..zip.len() {
        let name = zip.by_index(index)?.name().to_owned();
        if name != "manifest.json" && !listed.contains(name.as_str()) {
            bail!("archive entry is not covered by manifest checksums: {name}")
        }
    }
    Ok(())
}
