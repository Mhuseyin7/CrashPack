use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};

pub const STARTER_CONFIG: &str = r#"version: 1
application:
  name: MyApplication
  version: unknown
collect:
  system: true
  runtime: true
  docker: false # When enabled, collects version and container names/state only.
  environment:
    names: [] # Names only by default.
    values_allowlist: [] # Values require explicit opt-in.
  network:
    endpoints: [] # Explicit host:port reachability/DNS checks only; no scanning.
  application_metadata: {} # Safe build/feature/plugin metadata only.
  files: [] # Explicit paths only; add e.g. { path: ./logs/app.log, max_bytes: 5000000 }
  commands: [] # Executable and argv only; shells are never used.
redaction:
  privacy_level: STRICT
  emails: true
  ip_addresses: true
  paths: true
  custom_patterns: []
limits:
  max_bundle_bytes: 52428800
  command_timeout_secs: 10
"#;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub version: u8,
    pub application: Application,
    #[serde(default)]
    pub collect: Collect,
    #[serde(default)]
    pub redaction: Redaction,
    #[serde(default)]
    pub limits: Limits,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Application {
    pub name: String,
    #[serde(default = "unknown")]
    pub version: String,
    #[serde(default)]
    pub commit: Option<String>,
}
fn unknown() -> String {
    "unknown".into()
}
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Collect {
    #[serde(default)]
    pub system: bool,
    #[serde(default)]
    pub runtime: bool,
    #[serde(default)]
    pub docker: bool,
    #[serde(default)]
    pub environment: EnvironmentRule,
    #[serde(default)]
    pub network: NetworkRule,
    #[serde(default)]
    pub application_metadata: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    pub files: Vec<FileRule>,
    #[serde(default)]
    pub commands: Vec<CommandRule>,
}
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentRule {
    #[serde(default)]
    pub names: Vec<String>,
    #[serde(default)]
    pub values_allowlist: Vec<String>,
}
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkRule {
    #[serde(default)]
    pub endpoints: Vec<NetworkEndpoint>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkEndpoint {
    pub name: String,
    pub host: String,
    pub port: u16,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileRule {
    pub path: String,
    #[serde(default = "default_max")]
    pub max_bytes: u64,
    #[serde(default)]
    pub tail: bool,
}
fn default_max() -> u64 {
    5_000_000
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandRule {
    pub name: String,
    pub executable: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default = "default_command_max")]
    pub max_bytes: u64,
}
fn default_command_max() -> u64 {
    1_000_000
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Redaction {
    #[serde(default = "strict")]
    pub privacy_level: PrivacyLevel,
    #[serde(default = "yes")]
    pub emails: bool,
    #[serde(default = "yes")]
    pub ip_addresses: bool,
    #[serde(default = "yes")]
    pub paths: bool,
    #[serde(default)]
    pub custom_patterns: Vec<String>,
}
fn yes() -> bool {
    true
}
fn strict() -> PrivacyLevel {
    PrivacyLevel::Strict
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum PrivacyLevel {
    Strict,
    Standard,
    Custom,
}
impl Default for Redaction {
    fn default() -> Self {
        Self {
            privacy_level: strict(),
            emails: true,
            ip_addresses: true,
            paths: true,
            custom_patterns: vec![],
        }
    }
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    #[serde(default = "bundle_max")]
    pub max_bundle_bytes: u64,
    #[serde(default = "timeout")]
    pub command_timeout_secs: u64,
}
fn bundle_max() -> u64 {
    50_000_000
}
fn timeout() -> u64 {
    10
}
fn validate_byte_limit(name: &str, value: u64) -> Result<()> {
    if value == 0 {
        bail!("{name} must be positive")
    }
    if value > i64::MAX as u64 || value > usize::MAX as u64 {
        bail!("{name} is too large for this platform")
    }
    Ok(())
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_bundle_bytes: bundle_max(),
            command_timeout_secs: timeout(),
        }
    }
}
impl Config {
    pub fn from_path(path: &Path) -> Result<Self> {
        let value: Self = serde_yaml::from_str(&fs::read_to_string(path)?)?;
        value.validate()?;
        Ok(value)
    }
    fn validate(&self) -> Result<()> {
        if self.version != 1 {
            bail!("only config version 1 is supported")
        }
        if self.application.name.trim().is_empty() {
            bail!("application.name cannot be empty")
        }
        validate_byte_limit("limits.max_bundle_bytes", self.limits.max_bundle_bytes)?;
        for f in &self.collect.files {
            if f.path.is_empty() || Path::new(&f.path).is_absolute() || f.path.contains("..") {
                bail!("file path must be a relative path without '..': {}", f.path)
            }
            validate_byte_limit("file max_bytes", f.max_bytes)?;
        }
        for c in &self.collect.commands {
            if c.name.trim().is_empty() || c.name.contains(['/', '\\', '\0']) {
                bail!("command name must be non-empty and path-safe")
            }
            validate_byte_limit("command max_bytes", c.max_bytes)?;
            if c.executable.trim().is_empty()
                || c.executable.contains(['/', '\\'])
                || c.executable.chars().any(char::is_whitespace)
            {
                bail!("command executable must be a bare program name")
            }
            if c.args.iter().any(|a| a.contains('\0')) {
                bail!("command args cannot contain NUL")
            }
        }
        for name in self
            .collect
            .environment
            .names
            .iter()
            .chain(self.collect.environment.values_allowlist.iter())
        {
            if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                bail!("environment variable names must use only letters, digits, and _: {name}")
            }
        }
        for endpoint in &self.collect.network.endpoints {
            if endpoint.name.trim().is_empty()
                || endpoint.host.trim().is_empty()
                || endpoint.port == 0
                || endpoint.name.contains(['/', '\\', '\0'])
            {
                bail!("network endpoints require a path-safe name, host, and non-zero port")
            }
        }
        for (key, value) in &self.collect.application_metadata {
            if key.trim().is_empty() || key.contains(['\n', '\r', '\0']) || value.contains('\0') {
                bail!("application metadata contains an invalid key or value")
            }
        }
        for p in &self.redaction.custom_patterns {
            let regex = regex::Regex::new(p).context("invalid custom redaction regex")?;
            if regex.is_match("") {
                bail!("custom redaction regex must not match an empty string")
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Config;
    use std::fs;

    #[test]
    fn rejects_parent_paths_and_shell_like_executables() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("crashpack.yml");
        fs::write(&path, "version: 1\napplication: { name: test }\ncollect:\n  files: [{ path: ../secret.log }]\n").unwrap();
        assert!(Config::from_path(&path).is_err());
        fs::write(&path, "version: 1\napplication: { name: test }\ncollect:\n  commands: [{ name: nope, executable: 'sh -c' }]\n").unwrap();
        assert!(Config::from_path(&path).is_err());
    }

    #[test]
    fn rejects_empty_matching_redaction_rules_and_unsafe_names() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("crashpack.yml");
        fs::write(
            &path,
            "version: 1\napplication: { name: test }\nredaction: { custom_patterns: ['.*'] }\n",
        )
        .unwrap();
        assert!(Config::from_path(&path).is_err());
        fs::write(&path, "version: 1\napplication: { name: test }\ncollect:\n  commands: [{ name: 'bad/name', executable: echo }]\n").unwrap();
        assert!(Config::from_path(&path).is_err());
    }
}
