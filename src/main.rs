use std::io::{BufRead, BufReader, Write};
use std::process::ExitCode;

use anyhow::{Result, anyhow, bail};
use clap::{Parser, Subcommand};

use hush::vault::Binding;
use hush::{harden, names, run, vault};

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

/// Asks a yes/no question on the terminal, defaulting to no. Like the
/// passphrase prompt, it uses the terminal rather than stdin.
fn confirm(question: &str) -> Result<bool> {
    let mut tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|_| anyhow!("no terminal to confirm on"))?;
    write!(tty, "{question} [y/N] ")?;
    tty.flush()?;
    let mut answer = String::new();
    BufReader::new(&tty).read_line(&mut answer)?;
    Ok(matches!(answer.trim(), "y" | "Y" | "yes"))
}

#[derive(Parser)]
#[command(
    name = "hush",
    version = env!("HUSH_VERSION"),
    about = "Placeholder-swap secrets for AI coding agents"
)]
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
        /// Also hand this secret to the command, on top of the project's
        /// `.env` and ~/.config/hush/global.env. Repeatable.
        #[arg(long = "secret", value_name = "NAME")]
        secrets: Vec<String>,
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
        /// Also swap over plain HTTP to a non-loopback host, sending the real
        /// value unencrypted. Off by default.
        #[arg(long)]
        allow_http: bool,
        /// Replace NAME, value and bindings, if it already exists, without
        /// asking first.
        #[arg(long)]
        force: bool,
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
        /// Also swap over plain HTTP to a non-loopback host, sending the real
        /// value unencrypted. Off by default.
        #[arg(long)]
        allow_http: bool,
    },
    /// Remove a secret.
    Rm { name: String },
    /// List secret names and their bindings (never values).
    Ls,
}

fn main() -> ExitCode {
    harden::process();
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
        Command::Run { env, secrets, cmd } => {
            let cwd = std::env::current_dir()?;
            let names = names::collect(&cwd, &vault::global_env_path()?, &secrets)?;
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
            allow_http,
            force,
        } => {
            vault::check_host(&host)?;
            let binding = Binding::new(host, env, header, format, allow_http);
            let replacing = if force {
                ", replacing it if it exists"
            } else {
                ""
            };
            eprintln!("adding {name}{replacing}, bound to {}", describe(&binding));
            let pass = passphrase()?;
            let _lock = vault::lock_vault()?;
            let mut v = vault::load_vault(&pass)?;
            if let Some(existing) = v.secrets.get(&name)
                && !force
            {
                eprintln!("{name} already exists, bound to:");
                for b in &existing.bindings {
                    eprintln!("  {}", describe(b));
                }
                let replace = confirm("replace its value and bindings?").map_err(|e| {
                    anyhow!("{name} already exists: {e}; pass --force to replace it")
                })?;
                if !replace {
                    bail!("left {name} unchanged");
                }
            }
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
            allow_http,
        } => {
            vault::check_host(&host)?;
            let binding = Binding::new(host, env, header, format, allow_http);
            eprintln!("binding {name} to {}", describe(&binding));
            let pass = passphrase()?;
            let _lock = vault::lock_vault()?;
            let mut v = vault::load_vault(&pass)?;
            let Some(entry) = v.secrets.get_mut(&name) else {
                bail!("no such secret: {name}")
            };
            entry
                .add_binding(binding)
                .map_err(|e| anyhow!("{name} is {e}"))?;
            vault::save_vault(&v, &pass)?;
        }
        SecretAction::Rm { name } => {
            eprintln!("removing {name}");
            let pass = passphrase()?;
            let _lock = vault::lock_vault()?;
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
    let http = if b.allow_http { " allow-http" } else { "" };
    format!(
        "[{env}] host={} header={} format=\"{}\"{http}",
        b.host, b.header, b.format
    )
}
