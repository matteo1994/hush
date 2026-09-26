mod agent;
mod client;
mod protocol;
mod proxy;
mod vault;

use std::collections::HashMap;
use std::fs;
use std::process::ExitCode;

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};

use protocol::Request;

/// Reads a secret input interactively (hidden), or from an env var for
/// scripting/testing — same escape hatch pattern as e.g. `murk --stdin`.
fn read_secret(prompt: &str, env_override: &str) -> Result<String> {
    if let Ok(v) = std::env::var(env_override) {
        return Ok(v);
    }
    Ok(rpassword::prompt_password(prompt)?)
}

#[derive(Parser)]
#[command(name = "hush", about = "Placeholder-swap secrets for AI coding agents")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new vault and set its passphrase.
    Init,
    /// Unlock the vault into a session-lived agent (like ssh-agent). Run this once per session.
    Unlock,
    /// Manage secrets in the vault.
    Secret {
        #[command(subcommand)]
        action: SecretAction,
    },
    /// Run a command with managed secrets swapped in on the wire, never in its own env.
    Run {
        #[arg(long)]
        env: Option<String>,
        #[arg(last = true, required = true)]
        cmd: Vec<String>,
    },
}

#[derive(Subcommand)]
enum SecretAction {
    /// Add a new secret and its host binding (prompts for the value, hidden).
    Add {
        name: String,
        #[arg(long)]
        host: String,
        #[arg(long)]
        env: Option<String>,
        #[arg(long)]
        header: Option<String>,
        #[arg(long)]
        format: Option<String>,
    },
    /// Add another host binding to an existing secret.
    Bind {
        name: String,
        #[arg(long)]
        host: String,
        #[arg(long)]
        env: Option<String>,
        #[arg(long)]
        header: Option<String>,
        #[arg(long)]
        format: Option<String>,
    },
    /// Remove a secret.
    Rm { name: String },
    /// List secret names and their bindings (never values).
    Ls,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("hush: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode> {
    match cli.command {
        Command::Init => cmd_init(),
        Command::Unlock => cmd_unlock(),
        Command::Secret { action } => cmd_secret(action),
        Command::Run { env, cmd } => cmd_run(env, cmd),
    }
}

fn cmd_init() -> Result<ExitCode> {
    if vault::vault_exists()? {
        bail!("vault already exists at {}", vault::vault_path()?.display());
    }
    let pass1 = read_secret("New passphrase: ", "HUSH_PASSPHRASE")?;
    let pass2 = read_secret("Confirm passphrase: ", "HUSH_PASSPHRASE")?;
    if pass1 != pass2 {
        bail!("passphrases did not match");
    }
    if pass1.is_empty() {
        bail!("passphrase must not be empty");
    }
    vault::init_vault(&pass1)?;
    println!("vault created at {}", vault::vault_path()?.display());
    println!("run `hush unlock` to start a session.");
    Ok(ExitCode::SUCCESS)
}

fn cmd_unlock() -> Result<ExitCode> {
    if !vault::vault_exists()? {
        bail!("no vault found — run `hush init` first");
    }
    let pass = read_secret("Passphrase: ", "HUSH_PASSPHRASE")?;
    let v = vault::load_vault(&pass)?;
    agent::run(v, pass)?;
    Ok(ExitCode::SUCCESS)
}

fn cmd_secret(action: SecretAction) -> Result<ExitCode> {
    match action {
        SecretAction::Add { name, host, env, header, format } => {
            let value = read_secret(&format!("Value for {name}: "), "HUSH_SECRET_VALUE")?;
            let resp = client::send(&Request::AddSecret { name, value, host, env, header, format })?;
            print_status(resp)
        }
        SecretAction::Bind { name, host, env, header, format } => {
            let resp = client::send(&Request::BindSecret { name, host, env, header, format })?;
            print_status(resp)
        }
        SecretAction::Rm { name } => {
            let resp = client::send(&Request::RemoveSecret { name })?;
            print_status(resp)
        }
        SecretAction::Ls => {
            let resp = client::send(&Request::ListSecrets)?;
            if let protocol::Response::SecretList { secrets } = resp {
                for s in secrets {
                    println!("{}", s.name);
                    for b in s.bindings {
                        let env_label = b.env.unwrap_or_else(|| "default".to_string());
                        println!("  [{env_label}] host={} header={} format=\"{}\"", b.host, b.header, b.format);
                    }
                }
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn print_status(resp: protocol::Response) -> Result<ExitCode> {
    match resp {
        protocol::Response::Ok => Ok(ExitCode::SUCCESS),
        protocol::Response::Error { message } => {
            eprintln!("hush: {message}");
            Ok(ExitCode::FAILURE)
        }
        _ => Ok(ExitCode::SUCCESS),
    }
}

fn cmd_run(env: Option<String>, cmd: Vec<String>) -> Result<ExitCode> {
    let names = find_managed_keys()?;

    let mut child_env: HashMap<String, String> = std::env::vars().collect();

    if !names.is_empty() {
        let resp = client::send(&Request::Mint { names, env })?;
        match resp {
            protocol::Response::Minted { proxy_port, placeholders, unmatched } => {
                for name in &unmatched {
                    eprintln!("hush: warning: {name} has no matching binding, not injected");
                }
                for (name, placeholder) in placeholders {
                    child_env.insert(name, placeholder);
                }
                let proxy_url = format!("http://127.0.0.1:{proxy_port}");
                child_env.insert("HTTP_PROXY".to_string(), proxy_url.clone());
                child_env.insert("http_proxy".to_string(), proxy_url);
            }
            protocol::Response::Error { message } => bail!(message),
            _ => {}
        }
    }

    let (program, args) = cmd.split_first().expect("clap requires at least one cmd arg");
    let status = std::process::Command::new(program)
        .args(args)
        .env_clear()
        .envs(&child_env)
        .status()?;

    Ok(ExitCode::from(status.code().unwrap_or(1) as u8))
}

/// Scans `.env` in the current directory for `_KEY`-suffixed names.
/// Values are ignored entirely — hush never reads a real secret from `.env`.
fn find_managed_keys() -> Result<Vec<String>> {
    let path = std::path::Path::new(".env");
    if !path.exists() {
        return Ok(Vec::new());
    }
    let content = fs::read_to_string(path)?;
    let mut names = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, _)) = line.split_once('=') {
            let key = key.trim();
            if key.ends_with("_KEY") {
                names.push(key.to_string());
            }
        }
    }
    Ok(names)
}
