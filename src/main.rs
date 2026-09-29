mod proxy;
mod run;
mod tls;
mod vault;

use std::fs;
use std::process::ExitCode;

use anyhow::{Result, bail};
use clap::{Parser, Subcommand};

use vault::Binding;

/// Reads a secret input interactively (hidden), or from an env var for
/// scripting/testing — same escape hatch pattern as e.g. `murk --stdin`.
fn read_secret(prompt: &str, env_override: &str) -> Result<String> {
    if let Ok(v) = std::env::var(env_override) {
        return Ok(v);
    }
    rpassword::prompt_password(prompt).map_err(|e| match e.raw_os_error() {
        Some(libc::ENXIO) => anyhow::anyhow!(
            "no terminal to prompt on for {}",
            prompt.trim_end_matches([':', ' '])
        ),
        _ => e.into(),
    })
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
    /// Manage secrets in the vault.
    Secret {
        #[command(subcommand)]
        action: SecretAction,
    },
    /// Run a command with managed secrets swapped in on the wire, never in its own env.
    /// Prompts for the passphrase when `.env` names any managed secret.
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
    match dispatch(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("hush: {e}");
            ExitCode::FAILURE
        }
    }
}

fn dispatch(cli: Cli) -> Result<ExitCode> {
    match cli.command {
        Command::Init => cmd_init(),
        Command::Secret { action } => cmd_secret(action),
        Command::Run { env, cmd } => {
            let names = find_managed_keys()?;
            run::run(names, env, cmd, passphrase)
        }
    }
}

fn passphrase() -> Result<String> {
    if !vault::vault_exists()? {
        bail!("no vault found — run `hush init` first");
    }
    read_secret("Vault passphrase: ", "HUSH_PASSPHRASE")
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
    println!("add a secret with `hush secret add NAME --host HOST`.");
    Ok(ExitCode::SUCCESS)
}

/// Every vault change needs the passphrase, so a process started by
/// `hush run` can't rebind a secret to a host it controls. The change is
/// printed before the prompt so you can see what you're approving.
fn cmd_secret(action: SecretAction) -> Result<ExitCode> {
    if std::env::var_os(run::ACTIVE_VAR).is_some() && !matches!(action, SecretAction::Ls) {
        eprintln!(
            "hush: WARNING: this is running inside `hush run`, possibly started by an agent rather than you."
        );
        eprintln!("hush: only enter the passphrase if you typed this command yourself.");
    }

    match action {
        SecretAction::Add {
            name,
            host,
            env,
            header,
            format,
        } => {
            let binding = Binding::new(host, env, header, format);
            eprintln!("adding {name}, bound to {}", describe(&binding));
            let pass = passphrase()?;
            let mut v = vault::load_vault(&pass)?;
            let value = read_secret(&format!("Value for {name}: "), "HUSH_SECRET_VALUE")?;
            v.secrets.insert(
                name,
                vault::SecretEntry {
                    value,
                    bindings: vec![binding],
                },
            );
            vault::save_vault(&v, &pass)?;
        }
        SecretAction::Bind {
            name,
            host,
            env,
            header,
            format,
        } => {
            let binding = Binding::new(host, env, header, format);
            eprintln!("binding {name} to {}", describe(&binding));
            let pass = passphrase()?;
            let mut v = vault::load_vault(&pass)?;
            let Some(entry) = v.secrets.get_mut(&name) else {
                bail!("no such secret: {name}")
            };
            entry.bindings.push(binding);
            vault::save_vault(&v, &pass)?;
        }
        SecretAction::Rm { name } => {
            eprintln!("removing {name}");
            let pass = passphrase()?;
            let mut v = vault::load_vault(&pass)?;
            if v.secrets.remove(&name).is_none() {
                bail!("no such secret: {name}");
            }
            vault::save_vault(&v, &pass)?;
        }
        SecretAction::Ls => {
            let v = vault::load_vault(&passphrase()?)?;
            let mut names: Vec<_> = v.secrets.keys().collect();
            names.sort();
            for name in names {
                println!("{name}");
                for b in &v.secrets[name].bindings {
                    println!("  {}", describe(b));
                }
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn describe(b: &Binding) -> String {
    let env = b.env.as_deref().unwrap_or("default");
    format!(
        "[{env}] host={} header={} format=\"{}\"",
        b.host, b.header, b.format
    )
}

/// Scans `.env` in the current directory for `_KEY`-suffixed names.
/// Values are ignored entirely — hush never reads a real secret from `.env`.
fn find_managed_keys() -> Result<Vec<String>> {
    let path = std::path::Path::new(".env");
    if !path.exists() {
        return Ok(Vec::new());
    }
    Ok(managed_keys(&fs::read_to_string(path)?))
}

fn managed_keys(dotenv: &str) -> Vec<String> {
    let mut names = Vec::new();
    for line in dotenv.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, _)) = line.split_once('=')
            && key.trim().ends_with("_KEY")
        {
            names.push(key.trim().to_string());
        }
    }
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn managed_keys_are_key_suffixed_names_only() {
        let dotenv = "# comment\n\nBILLING_API_KEY=\n  STRIPE_SECRET_KEY = sk_ignored\nDATABASE_URL=postgres://\nKEYRING=x\nnot a pair\n";
        assert_eq!(
            managed_keys(dotenv),
            vec!["BILLING_API_KEY", "STRIPE_SECRET_KEY"]
        );
    }
}
