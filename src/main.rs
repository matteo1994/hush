use std::io::{BufRead, BufReader, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand};

use hush::vault::Binding;
use hush::{harden, names, run, vault};

/// Reads a secret input interactively (hidden), or from an env var for
/// scripting/testing — same escape hatch pattern as e.g. `murk --stdin`.
fn read_secret(prompt: &str, env_override: &str) -> Result<String> {
    if let Ok(v) = std::env::var(env_override) {
        return Ok(v);
    }
    warn_if_inside_run();
    #[cfg(target_os = "macos")]
    warn_if_not_hardened();
    rpassword::prompt_password(prompt).map_err(|e| match e.raw_os_error() {
        Some(libc::ENXIO) => anyhow::anyhow!(
            "no terminal to prompt on for {}",
            prompt.trim_end_matches([':', ' '])
        ),
        _ => e.into(),
    })
}

/// Before the first prompt inside `hush run`: a command there may have been
/// started by an agent, which shares the terminal and can read what's typed
/// into the prompt. That holds for every prompt, `secret ls` included, not
/// only for vault changes.
fn warn_if_inside_run() {
    static WARNED: std::sync::Once = std::sync::Once::new();
    if std::env::var_os(run::ACTIVE_VAR).is_some() {
        WARNED.call_once(|| {
            eprintln!(
                "hush: WARNING: this is running inside `hush run`, possibly started by an agent rather than you."
            );
            eprintln!("hush: only enter the passphrase if you typed this command yourself.");
        });
    }
}

/// Before the first prompt of a hush without the hardened runtime: a library
/// in `DYLD_INSERT_LIBRARIES`, set by anything that can edit your shell's
/// startup files, would run inside it and see what's typed.
#[cfg(target_os = "macos")]
fn warn_if_not_hardened() {
    static WARNED: std::sync::Once = std::sync::Once::new();
    if !harden::hardened_runtime() {
        WARNED.call_once(|| {
            eprintln!(
                "hush: warning: this hush isn't signed with the hardened runtime, so a library another program injects could read the passphrase."
            );
            eprintln!(
                "hush: sign it once per install: sudo codesign -f -s - -o runtime \"$(command -v hush)\""
            );
        });
    }
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
    /// Change the vault passphrase.
    Passwd,
    /// Manage secrets in the vault.
    Secret {
        #[command(subcommand)]
        action: SecretAction,
    },
    /// Choose which profile `hush run` uses in a project.
    Profile {
        #[command(subcommand)]
        action: ProfileAction,
    },
    /// Run a command with managed secrets swapped in on the wire, never in its own env.
    /// Prompts for the passphrase when `.env` names any managed secret.
    Run {
        /// Use this profile's entries, and the unprofiled ones for names it
        /// doesn't have. Overrides the profile `hush profile use` mapped to
        /// this project.
        #[arg(long, value_name = "NAME")]
        profile: Option<String>,
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
        /// asking first. To replace only the value, use `secret set`.
        #[arg(long)]
        force: bool,
        /// Warn from `hush run` once the value is older than this (`90d`,
        /// `12h`, `30m`). The clock starts when the value is set.
        #[arg(long, value_name = "DURATION")]
        max_age: Option<String>,
        /// Work on this profile's entries instead of the unprofiled ones.
        #[arg(long, value_name = "NAME")]
        profile: Option<String>,
    },
    /// Replace a secret's value and keep its bindings.
    Set {
        name: String,
        /// Read one value from stdin instead of prompting. A single trailing
        /// newline is removed; the rest, spaces included, is the value.
        #[arg(long)]
        stdin: bool,
        /// Warn from `hush run` once the value is older than this (`90d`,
        /// `12h`, `30m`), or `none` to clear a limit. Omit to leave it.
        #[arg(long, value_name = "DURATION")]
        max_age: Option<String>,
        /// Keep redacting the previous value from responses for this long
        /// (`7d`, `12h`). It is never sent. Without this, it is forgotten.
        #[arg(long, value_name = "DURATION")]
        keep_old: Option<String>,
        /// Work on this profile's entries instead of the unprofiled ones.
        #[arg(long, value_name = "NAME")]
        profile: Option<String>,
    },
    /// Copy a secret, with its bindings, to another profile or to the
    /// unprofiled entries. The copy is separate: rotate each one.
    Cp {
        name: String,
        /// The profile to copy from. Leave out for the unprofiled entries.
        #[arg(long, value_name = "PROFILE")]
        from: Option<String>,
        /// The profile to copy to. Leave out for the unprofiled entries.
        #[arg(long, value_name = "PROFILE")]
        to: Option<String>,
        /// Replace NAME at the destination if it is already there.
        #[arg(long)]
        force: bool,
    },
    /// Move a secret, with its bindings, to another profile or to the
    /// unprofiled entries.
    Mv {
        name: String,
        /// The profile to move from. Leave out for the unprofiled entries.
        #[arg(long, value_name = "PROFILE")]
        from: Option<String>,
        /// The profile to move to. Leave out for the unprofiled entries.
        #[arg(long, value_name = "PROFILE")]
        to: Option<String>,
        /// Replace NAME at the destination if it is already there.
        #[arg(long)]
        force: bool,
    },
    /// Remove one host binding from a secret.
    Unbind {
        name: String,
        #[arg(long)]
        host: String,
        #[arg(long)]
        env: Option<String>,
        /// Work on this profile's entries instead of the unprofiled ones.
        #[arg(long, value_name = "NAME")]
        profile: Option<String>,
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
        /// Work on this profile's entries instead of the unprofiled ones.
        #[arg(long, value_name = "NAME")]
        profile: Option<String>,
    },
    /// Remove a secret.
    Rm {
        name: String,
        /// Work on this profile's entries instead of the unprofiled ones.
        #[arg(long, value_name = "NAME")]
        profile: Option<String>,
    },
    /// List secret names, how old each value is, and their bindings (never
    /// the values), and the profile of each. With --profile, what a run with
    /// that profile gets: its own entries and the unprofiled ones it doesn't
    /// replace.
    Ls {
        #[arg(long, value_name = "NAME")]
        profile: Option<String>,
    },
}

#[derive(Subcommand)]
enum ProfileAction {
    /// Make `hush run` in this project (its git root, else this directory)
    /// use profile NAME.
    Use {
        #[arg(required_unless_present = "none", conflicts_with = "none")]
        name: Option<String>,
        /// Remove the mapping instead, so runs there use the unprofiled entries.
        #[arg(long)]
        none: bool,
        /// Map this directory rather than the current project, or with
        /// --none, remove its mapping (it needn't exist any more).
        #[arg(long, value_name = "DIR")]
        dir: Option<PathBuf>,
    },
    /// List profiles, how many entries each holds and the directories
    /// mapped to it.
    Ls,
}

fn main() -> ExitCode {
    harden::process();
    let cli = Cli::parse();
    match dispatch(cli) {
        Ok(code) => code,
        Err(e) => {
            // Only the outermost message, not the cause chain (`{e:#}`): a
            // serde error quotes the vault value it rejected, and inside
            // `hush run` an agent can read this terminal.
            eprintln!("hush: {e}");
            ExitCode::FAILURE
        }
    }
}

fn dispatch(cli: Cli) -> Result<ExitCode> {
    match cli.command {
        Command::Init => cmd_init(),
        Command::Passwd => cmd_passwd(),
        Command::Secret { action } => cmd_secret(action),
        Command::Profile { action } => cmd_profile(action),
        Command::Run {
            profile,
            env,
            secrets,
            cmd,
        } => {
            profile_arg(profile.as_deref())?;
            // Canonical, as the directories `hush profile use` maps are.
            let cwd = std::env::current_dir()?.canonicalize()?;
            let names = names::collect(&cwd, &vault::global_env_path()?, &secrets)?;
            run::run(names, profile, &cwd, env, cmd, passphrase)
        }
    }
}

fn passphrase() -> Result<String> {
    if !vault::vault_exists()? {
        bail!("no vault found — run `hush init` first");
    }
    read_secret("Vault passphrase: ", "HUSH_PASSPHRASE")
}

/// A new passphrase for `init` or `passwd` must be confirmed and non-empty.
/// Neither is echoed in the error.
fn check_new_passphrase(pass: &str, confirm: &str) -> Result<()> {
    if pass != confirm {
        bail!("passphrases did not match");
    }
    if pass.is_empty() {
        bail!("passphrase must not be empty");
    }
    Ok(())
}

/// One value from stdin. Only a trailing newline is removed: the value may
/// itself contain spaces or newlines, and trimming further would change it.
fn read_stdin_value() -> Result<String> {
    let mut buf = String::new();
    std::io::stdin()
        .read_to_string(&mut buf)
        .context("reading the value from stdin")?;
    Ok(trim_trailing_newline(&buf).to_string())
}

fn trim_trailing_newline(buf: &str) -> &str {
    match buf.strip_suffix('\n') {
        Some(buf) => buf.strip_suffix('\r').unwrap_or(buf),
        None => buf,
    }
}

fn cmd_init() -> Result<ExitCode> {
    if vault::vault_exists()? {
        bail!("vault already exists at {}", vault::vault_path()?.display());
    }
    let pass1 = read_secret("New passphrase: ", "HUSH_PASSPHRASE")?;
    let pass2 = read_secret("Confirm passphrase: ", "HUSH_PASSPHRASE")?;
    check_new_passphrase(&pass1, &pass2)?;
    vault::init_vault(&pass1)?;
    println!("vault created at {}", vault::vault_path()?.display());
    println!("add a secret with `hush secret add NAME --host HOST`.");
    Ok(ExitCode::SUCCESS)
}

/// Re-encrypts the vault. The new passphrase is asked for only after the
/// current one has opened it, so a typo there doesn't collect a replacement.
fn cmd_passwd() -> Result<ExitCode> {
    eprintln!("changing the vault passphrase");
    let old = passphrase()?;
    let _lock = vault::lock_vault()?;
    let vault = vault::load_vault(&old)?;
    let new = read_secret("New passphrase: ", "HUSH_NEW_PASSPHRASE")?;
    let confirm = read_secret("Confirm passphrase: ", "HUSH_NEW_PASSPHRASE")?;
    check_new_passphrase(&new, &confirm)?;
    vault::save_vault(&vault, &new)?;
    println!("vault passphrase changed");
    Ok(ExitCode::SUCCESS)
}

/// `90d`, or `none` to store no limit. Checked before the passphrase prompt.
fn parse_max_age(text: &str) -> Result<Option<u64>> {
    if text.eq_ignore_ascii_case("none") {
        return Ok(None);
    }
    Ok(Some(vault::parse_duration(text)?))
}

fn no_such_secret(name: &str, profile: Option<&str>) -> anyhow::Error {
    let profile_flag = match profile {
        Some(p) => format!(" --profile {p}"),
        None => String::new(),
    };
    anyhow!(
        "no such secret: {name}{}; add it with `hush secret add {name} --host HOST{profile_flag}`",
        in_profile(profile)
    )
}

/// Every vault change needs the passphrase, so a process started by
/// `hush run` can't rebind a secret to a host it controls or replace its
/// value. The change is printed before the prompt so you can see what
/// you're approving.
fn cmd_secret(action: SecretAction) -> Result<ExitCode> {
    match action {
        SecretAction::Add {
            name,
            host,
            env,
            header,
            format,
            allow_http,
            force,
            max_age,
            profile,
        } => {
            let profile = profile_arg(profile.as_deref())?;
            vault::check_host(&host)?;
            let max_age_secs = match &max_age {
                Some(text) => parse_max_age(text)?,
                None => None,
            };
            let binding = Binding::new(host, env, header, format, allow_http);
            let replacing = if force {
                ", replacing it if it exists"
            } else {
                ""
            };
            eprintln!(
                "adding {name}{}{replacing}, bound to {}",
                in_profile(profile),
                describe(&binding)
            );
            if max_age_secs.is_some() {
                eprintln!(
                    "hush run will warn once {name} is older than {}",
                    max_age.as_deref().unwrap_or_default()
                );
            }
            let pass = passphrase()?;
            let _lock = vault::lock_vault()?;
            let mut v = vault::load_vault(&pass)?;
            if let Some(p) = profile
                && v.secrets.contains_key(&name)
            {
                eprintln!(
                    "runs with profile {p} will use this {name} instead of the unprofiled one"
                );
            }
            if let Some(existing) = v.secrets_in(profile).and_then(|s| s.get(&name))
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
            v.secrets_in_or_new(profile).insert(
                name,
                vault::SecretEntry {
                    value,
                    bindings: vec![binding],
                    rotated_at: Some(vault::now_unix()),
                    max_age_secs,
                    retired: Vec::new(),
                },
            );
            vault::save_vault(&v, &pass)?;
        }
        SecretAction::Set {
            name,
            stdin,
            max_age,
            keep_old,
            profile,
        } => {
            let profile = profile_arg(profile.as_deref())?;
            // `None` means leave the stored limit alone; `Some(None)` clears it.
            let max_age_secs = match &max_age {
                Some(text) => Some(parse_max_age(text)?),
                None => None,
            };
            // Before the passphrase, so a bad duration changes nothing and
            // doesn't consume a value waiting on stdin.
            let keep_for = match keep_old.as_deref() {
                Some(text) => Some(vault::parse_duration(text)?),
                None => None,
            };
            // Typed at a terminal, the value would echo, stay in the
            // scrollback, and be readable by an agent sharing the terminal.
            if stdin && std::io::stdin().is_terminal() {
                bail!(
                    "--stdin reads a piped value, and stdin is a terminal, where the value would echo; leave out --stdin to be prompted with the value hidden"
                );
            }
            eprintln!(
                "replacing the value of {name}{}, keeping its bindings",
                in_profile(profile)
            );
            if let Some(text) = &max_age {
                if text.eq_ignore_ascii_case("none") {
                    eprintln!("clearing the max age of {name}");
                } else {
                    eprintln!("hush run will warn once {name} is older than {text}");
                }
            }
            if let Some(text) = &keep_old {
                eprintln!(
                    "the previous value of {name} will be redacted from responses for {}, then dropped; it is never sent",
                    text.trim()
                );
            }
            let pass = passphrase()?;
            let _lock = vault::lock_vault()?;
            let mut v = vault::load_vault(&pass)?;
            // Copies made with `secret cp` keep the old value; say where.
            let others: Vec<String> = {
                let Some(existing) = v.secrets_in(profile).and_then(|s| s.get(&name)) else {
                    return Err(no_such_secret(&name, profile));
                };
                for b in &existing.bindings {
                    eprintln!("  {}", describe(b));
                }
                v.others_with_value(&name, profile, &existing.value)
                    .into_iter()
                    .map(|(p, n)| format!("{n}{}", vault::place(p)))
                    .collect()
            };
            let value = if stdin {
                read_stdin_value()?
            } else {
                read_secret(&format!("Value for {name}: "), "HUSH_SECRET_VALUE")?
            };
            // An empty pipe, say from a password manager command that failed,
            // would otherwise wipe the key.
            if value.is_empty() {
                bail!("the new value for {name} is empty; left it unchanged");
            }
            let Some(entry) = v.secrets_in_mut(profile).and_then(|s| s.get_mut(&name)) else {
                return Err(no_such_secret(&name, profile));
            };
            let changed = entry.value != value;
            let now = vault::now_unix();
            if let Some(secs) = keep_for {
                entry.retire_current(&value, vault::until_unix(now, secs), now);
            }
            entry.value = value;
            entry.rotated_at = Some(now);
            if let Some(max_age_secs) = max_age_secs {
                entry.max_age_secs = max_age_secs;
            }
            vault::save_vault(&v, &pass)?;
            if changed {
                for other in &others {
                    eprintln!("{other} held the same value and still does; set it there too");
                }
            }
        }
        SecretAction::Cp {
            name,
            from,
            to,
            force,
        } => copy_or_move(&name, from.as_deref(), to.as_deref(), force, false)?,
        SecretAction::Mv {
            name,
            from,
            to,
            force,
        } => copy_or_move(&name, from.as_deref(), to.as_deref(), force, true)?,
        SecretAction::Unbind {
            name,
            host,
            env,
            profile,
        } => {
            let profile = profile_arg(profile.as_deref())?;
            let env_for = env
                .as_deref()
                .map(|e| format!(" and env {e}"))
                .unwrap_or_default();
            eprintln!(
                "removing the binding of {name}{} for host {host}{env_for}",
                in_profile(profile)
            );
            let pass = passphrase()?;
            let _lock = vault::lock_vault()?;
            let mut v = vault::load_vault(&pass)?;
            let Some(entry) = v.secrets_in_mut(profile).and_then(|s| s.get_mut(&name)) else {
                bail!("no such secret: {name}{}", in_profile(profile))
            };
            entry
                .remove_binding(&host, env.as_deref())
                .map_err(|e| anyhow!("{name}: {e}"))?;
            if entry.bindings.is_empty() {
                eprintln!("{name} has no bindings left, so `hush run` will not inject it");
            }
            vault::save_vault(&v, &pass)?;
        }
        SecretAction::Bind {
            name,
            host,
            env,
            header,
            format,
            allow_http,
            profile,
        } => {
            let profile = profile_arg(profile.as_deref())?;
            vault::check_host(&host)?;
            let binding = Binding::new(host, env, header, format, allow_http);
            eprintln!(
                "binding {name}{} to {}",
                in_profile(profile),
                describe(&binding)
            );
            let pass = passphrase()?;
            let _lock = vault::lock_vault()?;
            let mut v = vault::load_vault(&pass)?;
            let Some(entry) = v.secrets_in_mut(profile).and_then(|s| s.get_mut(&name)) else {
                bail!("no such secret: {name}{}", in_profile(profile))
            };
            entry
                .add_binding(binding)
                .map_err(|e| anyhow!("{name} is {e}"))?;
            vault::save_vault(&v, &pass)?;
        }
        SecretAction::Rm { name, profile } => {
            let profile = profile_arg(profile.as_deref())?;
            eprintln!("removing {name}{}", in_profile(profile));
            let pass = passphrase()?;
            let _lock = vault::lock_vault()?;
            let mut v = vault::load_vault(&pass)?;
            if v.remove(&name, profile).is_none() {
                bail!("no such secret: {name}{}", in_profile(profile));
            }
            warn_if_emptied(&v, profile);
            vault::save_vault(&v, &pass)?;
        }
        SecretAction::Ls { profile } => {
            let profile = profile_arg(profile.as_deref())?;
            let v = vault::load_vault(&passphrase()?)?;
            // (profile, name), unprofiled first.
            let mut listed: Vec<(Option<&str>, &str)> = match profile {
                Some(p) => {
                    let Some(own) = v.secrets_in(Some(p)) else {
                        bail!("no such profile: {p}");
                    };
                    let shared = v.secrets.keys().filter(|n| !own.contains_key(*n));
                    shared
                        .map(|n| (None, n.as_str()))
                        .chain(own.keys().map(|n| (Some(p), n.as_str())))
                        .collect()
                }
                None => v
                    .secrets
                    .keys()
                    .map(|n| (None, n.as_str()))
                    .chain(v.profiles.iter().flat_map(|(p, profile)| {
                        profile
                            .secrets
                            .keys()
                            .map(|n| (Some(p.as_str()), n.as_str()))
                    }))
                    .collect(),
            };
            listed.sort();
            let now = vault::now_unix();
            for (p, name) in listed {
                match p {
                    Some(p) => println!("{name} (profile {p})"),
                    None => println!("{name}"),
                }
                let entry = &v.secrets_in(p).expect("listed from it")[name];
                println!("  {}", entry.age_label(now));
                if let Some(line) = entry.retired_label(now) {
                    println!("  {line}");
                }
                for b in &entry.bindings {
                    println!("  {}", describe(b));
                }
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_profile(action: ProfileAction) -> Result<ExitCode> {
    match action {
        ProfileAction::Use { name, none, dir } => {
            let name = profile_arg(name.as_deref())?;
            let dir = mapped_dir(dir.as_deref(), none)?;
            match name {
                Some(p) => eprintln!("mapping {dir} to profile {p}"),
                None => eprintln!("removing the profile mapping of {dir}"),
            }
            let pass = passphrase()?;
            let _lock = vault::lock_vault()?;
            let mut v = vault::load_vault(&pass)?;
            match name {
                Some(p) => {
                    if !v.profiles.contains_key(p) {
                        bail!(
                            "no such profile: {p}; add a secret to it first with `hush secret add NAME --host HOST --profile {p}`"
                        );
                    }
                    // Where the project was before it moved, perhaps. Not
                    // removed here: a directory on an unmounted volume looks
                    // just the same.
                    for (d, _) in v
                        .directories
                        .iter()
                        .filter(|(d, q)| *q == p && **d != dir && !Path::new(d).exists())
                    {
                        eprintln!(
                            "{d}, also mapped to {p}, no longer exists; if it's gone for good, `hush profile use --none --dir {d}`"
                        );
                    }
                    match v.directories.insert(dir.clone(), p.to_string()) {
                        Some(old) if old == p => {
                            eprintln!("{dir} was already mapped to profile {p}");
                            return Ok(ExitCode::SUCCESS);
                        }
                        Some(old) => eprintln!("it was mapped to profile {old}"),
                        None => {}
                    }
                }
                None => {
                    if v.directories.remove(&dir).is_none() {
                        match v.mapped_profile(Path::new(&dir)) {
                            Some((above, p)) => bail!(
                                "no profile is mapped to {dir} itself; runs there use profile {p}, mapped to {above}"
                            ),
                            None => bail!("no profile is mapped to {dir}"),
                        }
                    }
                }
            }
            vault::save_vault(&v, &pass)?;
        }
        ProfileAction::Ls => {
            let v = vault::load_vault(&passphrase()?)?;
            let mut names: Vec<&str> = v
                .profiles
                .keys()
                .chain(v.directories.values())
                .map(String::as_str)
                .collect();
            names.sort();
            names.dedup();
            if names.is_empty() {
                eprintln!(
                    "no profiles; add a secret to one with `hush secret add NAME --host HOST --profile PROFILE`"
                );
            }
            for p in names {
                match v.profiles.get(p).map(|p| p.secrets.len()) {
                    Some(1) => println!("{p}: 1 entry"),
                    Some(n) => println!("{p}: {n} entries"),
                    None => println!("{p}: not in the vault, runs use the unprofiled entries"),
                }
                for dir in v
                    .directories
                    .iter()
                    .filter(|(_, q)| *q == p)
                    .map(|(d, _)| d)
                {
                    if Path::new(dir).exists() {
                        println!("  {dir}");
                    } else {
                        println!("  {dir} (no longer exists)");
                    }
                }
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// The directory `profile use` maps: `--dir`, or else the current project.
/// Canonical, so a run finds it whatever symlinks led there. With `--none`
/// it may be gone: that's how a deleted project's mapping is removed.
fn mapped_dir(dir: Option<&Path>, none: bool) -> Result<String> {
    let cwd = std::env::current_dir()?.canonicalize()?;
    let dir = match dir {
        Some(d) => match d.canonicalize() {
            Ok(c) if !c.is_dir() => bail!("--dir {}: not a directory", d.display()),
            Ok(c) => c,
            Err(_) if none => canonical_gone(&cwd.join(d)),
            Err(e) => return Err(e).with_context(|| format!("--dir {}", d.display())),
        },
        None => names::project_dir(&cwd).to_path_buf(),
    };
    dir.into_os_string().into_string().map_err(|d| {
        anyhow!(
            "{}: hush can only map a directory whose path is UTF-8",
            d.display()
        )
    })
}

/// A path that doesn't exist, spelled as it was stored when it did: `.` and
/// `..` resolved, and its deepest existing ancestor canonicalized.
fn canonical_gone(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut lexical = PathBuf::new();
    for c in path.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                lexical.pop();
            }
            c => lexical.push(c),
        }
    }
    let mut rest = Vec::new();
    let mut base = lexical.as_path();
    loop {
        if let Ok(canonical) = base.canonicalize() {
            return rest.into_iter().rev().fold(canonical, |p, c| p.join(c));
        }
        match (base.parent(), base.file_name()) {
            (Some(parent), Some(name)) => {
                rest.push(name.to_owned());
                base = parent;
            }
            _ => return lexical,
        }
    }
}

/// `secret cp`, or with `remove_source`, `secret mv`. The whole entry goes,
/// bindings included, since a profile's entry replaces the unprofiled one
/// whole.
fn copy_or_move(
    name: &str,
    from: Option<&str>,
    to: Option<&str>,
    force: bool,
    remove_source: bool,
) -> Result<()> {
    let from = profile_arg(from)?;
    let to = profile_arg(to)?;
    let verb = if remove_source { "moving" } else { "copying" };
    let replacing = if force {
        ", replacing it there if it exists"
    } else {
        ""
    };
    eprintln!(
        "{verb} {name} with its bindings from{} to{}{replacing}",
        vault::place(from),
        vault::place(to)
    );
    let pass = passphrase()?;
    let _lock = vault::lock_vault()?;
    let mut v = vault::load_vault(&pass)?;
    if let Some(entry) = v.secrets_in(from).and_then(|s| s.get(name)) {
        for b in &entry.bindings {
            eprintln!("  {}", describe(b));
        }
    }
    if force && let Some(existing) = v.secrets_in(to).and_then(|s| s.get(name)) {
        let differs = v
            .secrets_in(from)
            .and_then(|s| s.get(name))
            .is_some_and(|e| e.value != existing.value);
        let what = if differs {
            "a different value"
        } else {
            "the same value"
        };
        eprintln!(
            "replacing {name}{}, which holds {what}, and its bindings:",
            vault::place(to)
        );
        for b in &existing.bindings {
            eprintln!("  {}", describe(b));
        }
        if differs {
            eprintln!("that value is dropped, not retired, so hush stops redacting it");
        }
    }
    if remove_source {
        v.move_entry(name, from, to, force)?;
        warn_if_emptied(&v, from);
    } else {
        v.copy_entry(name, from, to, force)?;
        eprintln!("the copy is separate: after `hush secret set`, set it in both places");
    }
    if let Some(p) = to
        && v.secrets.contains_key(name)
    {
        eprintln!("runs with profile {p} will use this {name} instead of the unprofiled one");
    }
    vault::save_vault(&v, &pass)?;
    Ok(())
}

/// After an entry left `profile`. Its directory mappings are kept, so adding
/// a secret to the profile again brings them back.
fn warn_if_emptied(v: &vault::Vault, profile: Option<&str>) {
    if let Some(p) = profile
        && !v.profiles.contains_key(p)
    {
        for (d, _) in v.directories.iter().filter(|(_, q)| *q == p) {
            eprintln!(
                "profile {p} is empty now and removed, but {d} is still mapped to it; runs there use the unprofiled entries"
            );
        }
    }
}

fn profile_arg(profile: Option<&str>) -> Result<Option<&str>> {
    if let Some(p) = profile {
        vault::check_profile(p)?;
    }
    Ok(profile)
}

fn in_profile(profile: Option<&str>) -> String {
    profile
        .map(|p| format!(" in profile {p}"))
        .unwrap_or_default()
}

fn describe(b: &Binding) -> String {
    let env = b.env.as_deref().unwrap_or("default");
    let http = if b.allow_http { " allow-http" } else { "" };
    format!(
        "[{env}] host={} header={} format=\"{}\"{http}",
        b.host, b.header, b.format
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_passphrase_must_be_nonempty_and_confirmed() {
        assert!(check_new_passphrase("a", "a").is_ok());
        let empty = check_new_passphrase("", "").unwrap_err().to_string();
        assert!(empty.contains("must not be empty"), "{empty}");
        let mismatch = check_new_passphrase("super-secret-new", "other-secret")
            .unwrap_err()
            .to_string();
        assert!(mismatch.contains("did not match"), "{mismatch}");
        assert!(!mismatch.contains("super-secret-new"), "{mismatch}");
        assert!(!mismatch.contains("other-secret"), "{mismatch}");
    }

    #[test]
    fn stdin_value_drops_one_trailing_newline() {
        assert_eq!(trim_trailing_newline("abc\n"), "abc");
        assert_eq!(trim_trailing_newline("abc\r\n"), "abc");
        assert_eq!(trim_trailing_newline("abc"), "abc");
        assert_eq!(trim_trailing_newline("a\nb\n"), "a\nb");
        assert_eq!(trim_trailing_newline("abc\n\n"), "abc\n");
        assert_eq!(trim_trailing_newline(" trailing \n"), " trailing ");
        assert_eq!(trim_trailing_newline("\n"), "");
    }
}
