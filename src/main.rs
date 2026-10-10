mod bundle;
mod config;
mod redact;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use config::Config;
use std::{
    fs,
    path::{Path, PathBuf},
};

#[derive(Parser)]
#[command(
    name = "crashpack",
    version,
    about = "Create safe, local diagnostic support bundles."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a conservative starter configuration.
    Init {
        #[arg(default_value = "crashpack.yml")]
        config: PathBuf,
    },
    /// Collect configured diagnostics and create a sanitized ZIP bundle.
    Collect {
        #[arg(short, long, default_value = "crashpack.yml")]
        config: PathBuf,
        #[arg(short, long, default_value = ".")]
        output: PathBuf,
    },
    /// Show what would be collected and its safety limits.
    Preview {
        #[arg(short, long, default_value = "crashpack.yml")]
        config: PathBuf,
    },
    /// Print a bundle manifest without extracting it.
    Inspect { bundle: PathBuf },
    /// Verify archive paths and manifest checksums.
    Verify { bundle: PathBuf },
    /// Validate configuration and report local tool availability.
    Doctor {
        #[arg(short, long, default_value = "crashpack.yml")]
        config: PathBuf,
    },
    /// Sanitize one file to stdout (or --output), never modifying the source.
    Redact {
        file: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(short, long, default_value = "crashpack.yml")]
        config: PathBuf,
    },
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

fn load(path: &Path) -> Result<Config> {
    Config::from_path(path).with_context(|| format!("invalid configuration: {}", path.display()))
}

fn config_root(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn run() -> Result<()> {
    match Cli::parse().command {
        Command::Init { config } => {
            if config.exists() {
                bail!("refusing to overwrite existing {}", config.display());
            }
            fs::write(&config, config::STARTER_CONFIG)?;
            println!(
                "Created {}. Review paths and commands before collecting.",
                config.display()
            );
        }
        Command::Collect { config, output } => {
            let cfg = load(&config)?;
            let path = bundle::collect(&cfg, config_root(&config), &output)?;
            println!("\nBundle: {}", path.display());
            println!("Local only: CrashPack never uploads data.");
        }
        Command::Preview { config } => {
            let cfg = load(&config)?;
            bundle::preview(&cfg, config_root(&config))?;
        }
        Command::Inspect { bundle } => bundle::inspect(&bundle)?,
        Command::Verify { bundle } => {
            bundle::verify(&bundle)?;
            println!("Verification passed.");
        }
        Command::Doctor { config } => {
            let cfg = load(&config)?;
            bundle::doctor(&cfg);
        }
        Command::Redact {
            file,
            output,
            config,
        } => {
            let cfg = load(&config)?;
            let input_size = fs::metadata(&file)?.len();
            if input_size > cfg.limits.max_bundle_bytes {
                bail!(
                    "redact input is {} bytes, above max_bundle_bytes ({})",
                    input_size,
                    cfg.limits.max_bundle_bytes
                );
            }
            let bytes = fs::read(&file)?;
            let mut engine = redact::Engine::new(&cfg.redaction);
            let clean = engine.sanitize(&bytes);
            if let Some(path) = output {
                fs::write(path, clean)?;
            } else {
                print!("{}", String::from_utf8_lossy(&clean));
            }
            eprintln!("{} redactions applied", engine.summary().total());
        }
    }
    Ok(())
}
