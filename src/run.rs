use std::collections::HashMap;
use std::fs;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, bail};
use rand::RngCore;

use crate::harden;
use crate::proxy::{ErrorLog, PlaceholderEntry, start_proxy};
use crate::tls::{self, Mitm, TrustFiles};
use crate::vault::{self, Vault};

/// Set in the child's environment so a nested `hush run` can tell it's inside one.
pub const ACTIVE_VAR: &str = "HUSH_ACTIVE";

/// hush's own inputs. They must never reach the child: `HUSH_PASSPHRASE`
/// in particular would let it decrypt the vault directly.
const SCRUBBED_VARS: &[&str] = &["HUSH_PASSPHRASE", "HUSH_SECRET_VALUE"];

pub struct Minted {
    /// placeholder → what to swap it for, and where.
    pub table: HashMap<String, PlaceholderEntry>,
    /// env var name → placeholder, for the child's environment.
    pub placeholders: HashMap<String, String>,
    pub unmatched: Vec<String>,
    /// Names bound to this machine by name or without a port, never sent.
    pub unusable_loopback: Vec<String>,
}

/// Mints a fresh placeholder for each requested name that has a binding for
/// `env`, in `profile`'s entry for the name or else its unprofiled one. Only
/// these entries outlive the vault, which is dropped after this.
pub fn mint(vault: &Vault, names: &[String], profile: Option<&str>, env: Option<&str>) -> Minted {
    let mut minted = Minted {
        table: HashMap::new(),
        placeholders: HashMap::new(),
        unmatched: Vec::new(),
        unusable_loopback: Vec::new(),
    };
    for name in names {
        match vault.find_binding(name, profile, env) {
            Some((entry, binding)) => {
                let placeholder = generate_placeholder();
                let (host, port) = binding.host_and_port();
                if vault::unusable_loopback(&host, port) {
                    minted.unusable_loopback.push(name.clone());
                }
                minted.table.insert(
                    placeholder.clone(),
                    PlaceholderEntry {
                        real_value: entry.value.clone(),
                        host,
                        port,
                        header: binding.header.clone(),
                        format: binding.format.clone(),
                        allow_http: binding.allow_http,
                    },
                );
                minted.placeholders.insert(name.clone(), placeholder);
            }
            None => minted.unmatched.push(name.clone()),
        }
    }
    minted
}

fn generate_placeholder() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("hush_ph_{hex}")
}

/// The child's environment: the parent's, minus hush's own inputs, plus
/// placeholders and — when a proxy is running — proxy and CA trust settings.
pub fn child_env(
    parent: impl IntoIterator<Item = (String, String)>,
    placeholders: &HashMap<String, String>,
    proxy: Option<(u16, &TrustFiles)>,
) -> HashMap<String, String> {
    let mut env: HashMap<String, String> = parent
        .into_iter()
        .filter(|(k, _)| !SCRUBBED_VARS.contains(&k.as_str()))
        .collect();
    env.extend(placeholders.iter().map(|(k, v)| (k.clone(), v.clone())));
    env.insert(ACTIVE_VAR.to_string(), "1".to_string());

    if let Some((port, trust)) = proxy {
        let proxy_url = format!("http://127.0.0.1:{port}");
        for var in ["HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"] {
            env.insert(var.to_string(), proxy_url.clone());
        }
        // These replace the default roots, so they get system roots + CA.
        let bundle = trust.bundle.display().to_string();
        for var in [
            "SSL_CERT_FILE",
            "REQUESTS_CA_BUNDLE",
            "CURL_CA_BUNDLE",
            "GIT_SSL_CAINFO",
        ] {
            env.insert(var.to_string(), bundle.clone());
        }
        // Node appends to its roots instead, and only honors proxy env vars when asked to.
        env.insert(
            "NODE_EXTRA_CA_CERTS".to_string(),
            trust.ca.display().to_string(),
        );
        env.insert("NODE_USE_ENV_PROXY".to_string(), "1".to_string());
    }
    env
}

/// Runs `cmd` with managed secrets swapped in on the wire. This process holds
/// the minted secrets and the CA key in memory and serves the proxy until
/// `cmd` exits; nothing outlives it.
pub fn run(
    names: Vec<String>,
    profile: Option<String>,
    cwd: &Path,
    env: Option<String>,
    cmd: Vec<String>,
    passphrase: impl FnOnce() -> Result<String>,
) -> Result<ExitCode> {
    if std::env::var_os(ACTIVE_VAR).is_some() {
        bail!(
            "already inside `hush run` — placeholders and the proxy are already set up here, \
             start a separate `hush run` from your own shell instead"
        );
    }
    if names.is_empty() {
        return spawn(&cmd, child_env(std::env::vars(), &HashMap::new(), None));
    }

    let minted = {
        let vault = vault::load_vault(&passphrase()?)?;
        let profile = profile.or_else(|| mapped_profile(&vault, cwd));
        // A mistyped --profile, or a mapped profile whose last entry was
        // removed, would otherwise quietly run with the unprofiled entries.
        if let Some(p) = &profile
            && !vault.profiles.contains_key(p)
        {
            eprintln!(
                "hush: warning: there is no profile {p} in the vault, using the unprofiled entries"
            );
        }
        mint(&vault, &names, profile.as_deref(), env.as_deref())
    };
    for name in &minted.unmatched {
        eprintln!("hush: warning: {name} has no matching binding, not injected");
    }
    for name in &minted.unusable_loopback {
        eprintln!(
            "hush: warning: {name} is bound to this machine without an address and port, so it is never sent; add it again with --host 127.0.0.1:PORT or [::1]:PORT"
        );
    }
    if minted.table.is_empty() {
        return spawn(&cmd, child_env(std::env::vars(), &HashMap::new(), None));
    }

    let (upstream_roots, system_roots) = tls::native_roots()?;
    let mitm = Arc::new(Mitm::new(upstream_roots)?);
    let run_dir = RunDir::create()?;
    let trust = tls::write_trust_files(&mitm, &system_roots, run_dir.path())?;
    let errors = Arc::new(ErrorLog::default());
    let port = start_proxy(Arc::new(Mutex::new(minted.table)), mitm, errors.clone())?;

    let code = spawn(
        &cmd,
        child_env(std::env::vars(), &minted.placeholders, Some((port, &trust))),
    );
    // Only now: while the child ran, the terminal was its to draw on.
    if let Some(summary) = errors.summary() {
        eprintln!("hush: {summary}");
    }
    code
}

/// The profile `hush profile use` mapped to `cwd` or the nearest directory
/// above it, said aloud since nothing on the command line shows it.
fn mapped_profile(vault: &Vault, cwd: &Path) -> Option<String> {
    if let Some((dir, p)) = vault.mapped_profile(cwd) {
        eprintln!("hush: using profile {p}, mapped to {dir}");
        return Some(p.to_string());
    }
    // A project that moved loses its mapping without a word otherwise. Only
    // directories named like this project: a moved one usually keeps its
    // name, and the rest are in `hush profile ls`.
    let name = crate::names::project_dir(cwd).file_name();
    for (dir, p) in &vault.directories {
        if Path::new(dir).file_name() == name && !Path::new(dir).exists() {
            eprintln!(
                "hush: warning: {dir}, mapped to profile {p}, no longer exists; if that project moved here, run `hush profile use {p}`"
            );
        }
    }
    None
}

fn spawn(cmd: &[String], env: HashMap<String, String>) -> Result<ExitCode> {
    let (program, args) = cmd
        .split_first()
        .expect("clap requires at least one cmd arg");
    let mut cmd = Command::new(program);
    cmd.args(args).env_clear().envs(&env);
    harden::restore_for_child(&mut cmd);
    let mut child = cmd.spawn().with_context(|| format!("starting {program}"))?;

    // Ctrl-C / Ctrl-\ go to the whole foreground process group. The child
    // decides what they mean (an interactive agent may just cancel a step);
    // this process must outlive it, or the proxy vanishes mid-session. Set
    // only after spawning, so the child keeps the default dispositions.
    unsafe {
        libc::signal(libc::SIGINT, libc::SIG_IGN);
        libc::signal(libc::SIGQUIT, libc::SIG_IGN);
    }

    let status = child.wait()?;
    let code = match (status.code(), status.signal()) {
        (Some(code), _) => code,
        (None, Some(sig)) => 128 + sig,
        (None, None) => 1,
    };
    Ok(ExitCode::from(code as u8))
}

/// A private directory for one run's CA files, removed when the run ends.
struct RunDir(PathBuf);

impl RunDir {
    fn create() -> Result<Self> {
        let runs = vault::runs_dir()?;
        fs::create_dir_all(&runs)?;
        vault::set_private_mode(&runs)?;
        sweep_stale(&runs);
        let dir = runs.join(std::process::id().to_string());
        // A leftover from a crashed run that had this pid holds only public certs.
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir(&dir)?;
        Ok(RunDir(dir))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

/// Removes directories left behind by runs that were killed before they could
/// clean up (they hold only public certs, so this is tidiness, not safety).
/// A directory is stale when no process with its pid exists any more; a live
/// pid, even a reused one, keeps its directory.
fn sweep_stale(runs: &Path) {
    let Ok(entries) = fs::read_dir(runs) else {
        return;
    };
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<libc::pid_t>().ok())
        else {
            continue;
        };
        if pid > 0 && !process_exists(pid) {
            let _ = fs::remove_dir_all(entry.path());
        }
    }
}

fn process_exists(pid: libc::pid_t) -> bool {
    // Signal 0 checks for existence without sending anything. EPERM means it
    // exists but belongs to someone else.
    let signalled = unsafe { libc::kill(pid, 0) } == 0;
    signalled || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

impl Drop for RunDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{Binding, SecretEntry};

    fn vault() -> Vault {
        let mut v = Vault::new();
        v.secrets.insert(
            "BILLING_API_KEY".to_string(),
            SecretEntry {
                value: "REAL".to_string(),
                bindings: vec![
                    Binding::new("api.example.com".into(), None, None, None, false),
                    Binding::new(
                        "staging.example.com".into(),
                        Some("staging".into()),
                        Some("X-Key".into()),
                        Some("{value}".into()),
                        false,
                    ),
                ],
            },
        );
        v.secrets.insert(
            "UNUSED_KEY".to_string(),
            SecretEntry {
                value: "OTHER".to_string(),
                bindings: vec![Binding::new(
                    "other.example.com".into(),
                    None,
                    None,
                    None,
                    false,
                )],
            },
        );
        v
    }

    #[test]
    fn reports_loopback_bindings_without_an_address_and_port() {
        let mut v = Vault::new();
        for (name, host) in [
            ("DEV_KEY", "localhost"),
            ("NAMED_KEY", "localhost:3000"),
            ("PORTED_KEY", "127.0.0.1:3000"),
        ] {
            v.secrets.insert(
                name.to_string(),
                SecretEntry {
                    value: "REAL".to_string(),
                    bindings: vec![Binding::new(host.into(), None, None, None, false)],
                },
            );
        }
        let names = ["DEV_KEY".into(), "NAMED_KEY".into(), "PORTED_KEY".into()];
        let m = mint(&v, &names, None, None);

        assert_eq!(
            m.unusable_loopback,
            vec!["DEV_KEY".to_string(), "NAMED_KEY".to_string()]
        );
        let ported = &m.table[&m.placeholders["PORTED_KEY"]];
        assert_eq!(
            (ported.host.as_str(), ported.port),
            ("127.0.0.1", Some(3000))
        );
    }

    #[test]
    fn mints_only_requested_names_and_reports_unmatched() {
        let m = mint(
            &vault(),
            &["BILLING_API_KEY".into(), "MISSING_KEY".into()],
            None,
            None,
        );

        assert_eq!(m.unmatched, vec!["MISSING_KEY".to_string()]);
        assert_eq!(m.placeholders.len(), 1);
        let ph = &m.placeholders["BILLING_API_KEY"];
        assert!(
            ph.starts_with("hush_ph_") && ph.len() == "hush_ph_".len() + 32,
            "{ph}"
        );
        // Secrets not named in .env never make it into the run's memory.
        assert_eq!(m.table.len(), 1);
        let entry = &m.table[ph];
        assert_eq!(
            (entry.real_value.as_str(), entry.host.as_str()),
            ("REAL", "api.example.com")
        );
        assert_eq!(
            (entry.header.as_str(), entry.format.as_str()),
            ("Authorization", "Bearer {value}")
        );
    }

    #[test]
    fn mint_selects_env_binding() {
        let m = mint(&vault(), &["BILLING_API_KEY".into()], None, Some("staging"));
        let entry = &m.table[&m.placeholders["BILLING_API_KEY"]];
        assert_eq!(
            (entry.host.as_str(), entry.header.as_str()),
            ("staging.example.com", "X-Key")
        );
    }

    #[test]
    fn mint_takes_the_profile_entry_and_unprofiled_ones_for_the_rest() {
        let mut v = vault();
        v.profiles.entry("acme".into()).or_default().secrets.insert(
            "BILLING_API_KEY".to_string(),
            SecretEntry {
                value: "ACME".to_string(),
                bindings: vec![Binding::new(
                    "acme.example.com".into(),
                    None,
                    None,
                    None,
                    false,
                )],
            },
        );
        let names = ["BILLING_API_KEY".into(), "UNUSED_KEY".into()];
        let m = mint(&v, &names, Some("acme"), None);
        let entry = |name: &str| {
            let e = &m.table[&m.placeholders[name]];
            (e.real_value.as_str(), e.host.as_str())
        };
        assert_eq!(entry("BILLING_API_KEY"), ("ACME", "acme.example.com"));
        assert_eq!(entry("UNUSED_KEY"), ("OTHER", "other.example.com"));
    }

    /// `--env` picks the binding inside the profile's entry. The unprofiled
    /// entry's staging binding goes with its own value, so it is never used
    /// for the profile's.
    #[test]
    fn mint_with_a_profile_and_env_picks_within_the_profile_entry() {
        let mut v = vault();
        let acme = v.profiles.entry("acme".into()).or_default();
        acme.secrets.insert(
            "BILLING_API_KEY".to_string(),
            SecretEntry {
                value: "ACME".to_string(),
                bindings: vec![
                    Binding::new("acme.example.com".into(), None, None, None, false),
                    Binding::new(
                        "qa.acme.example.com".into(),
                        Some("qa".into()),
                        None,
                        None,
                        false,
                    ),
                ],
            },
        );
        let names = ["BILLING_API_KEY".to_string()];
        let host = |env| {
            let m = mint(&v, &names, Some("acme"), env);
            let e = &m.table[&m.placeholders["BILLING_API_KEY"]];
            (e.real_value.clone(), e.host.clone())
        };
        assert_eq!(
            host(Some("qa")),
            ("ACME".into(), "qa.acme.example.com".into())
        );
        // No staging binding in acme's entry: its unscoped one, not the
        // unprofiled entry's staging.example.com.
        assert_eq!(
            host(Some("staging")),
            ("ACME".into(), "acme.example.com".into())
        );
    }

    #[test]
    fn placeholders_are_fresh_per_mint() {
        let names = ["BILLING_API_KEY".to_string()];
        assert_ne!(
            mint(&vault(), &names, None, None).placeholders,
            mint(&vault(), &names, None, None).placeholders
        );
    }

    fn parent() -> Vec<(String, String)> {
        [
            ("PATH", "/usr/bin"),
            ("HUSH_PASSPHRASE", "hunter2"),
            ("HUSH_SECRET_VALUE", "sk-live"),
            ("BILLING_API_KEY", "whatever-the-shell-had"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
    }

    #[test]
    fn child_env_scrubs_hush_inputs_and_sets_proxy_and_trust() {
        let placeholders =
            HashMap::from([("BILLING_API_KEY".to_string(), "hush_ph_x".to_string())]);
        let trust = TrustFiles {
            ca: "/run/ca.pem".into(),
            bundle: "/run/ca-bundle.pem".into(),
        };
        let env = child_env(parent(), &placeholders, Some((4242, &trust)));

        assert!(!env.contains_key("HUSH_PASSPHRASE"));
        assert!(!env.contains_key("HUSH_SECRET_VALUE"));
        assert_eq!(env["PATH"], "/usr/bin");
        assert_eq!(
            env["BILLING_API_KEY"], "hush_ph_x",
            "placeholder overrides the inherited value"
        );
        assert_eq!(env[ACTIVE_VAR], "1");
        for var in ["HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"] {
            assert_eq!(env[var], "http://127.0.0.1:4242", "{var}");
        }
        for var in [
            "SSL_CERT_FILE",
            "REQUESTS_CA_BUNDLE",
            "CURL_CA_BUNDLE",
            "GIT_SSL_CAINFO",
        ] {
            assert_eq!(env[var], "/run/ca-bundle.pem", "{var}");
        }
        assert_eq!(env["NODE_EXTRA_CA_CERTS"], "/run/ca.pem");
        assert_eq!(env["NODE_USE_ENV_PROXY"], "1");
    }

    #[test]
    fn sweep_removes_only_dirs_of_dead_processes() {
        let runs = std::env::temp_dir().join(format!("hush-sweep-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&runs);
        fs::create_dir_all(&runs).unwrap();

        let mut child = Command::new("true").spawn().unwrap();
        let dead = child.id().to_string();
        child.wait().unwrap();
        let alive = std::process::id().to_string();
        for name in [dead.as_str(), alive.as_str(), "not-a-pid"] {
            fs::create_dir(runs.join(name)).unwrap();
        }

        sweep_stale(&runs);

        assert!(!runs.join(&dead).exists(), "dead run's dir should be swept");
        assert!(runs.join(&alive).exists(), "live run's dir must be kept");
        assert!(
            runs.join("not-a-pid").exists(),
            "unrelated entries are left alone"
        );
        fs::remove_dir_all(&runs).unwrap();
    }

    #[test]
    fn child_env_without_proxy_still_scrubs() {
        let env = child_env(parent(), &HashMap::new(), None);
        assert!(!env.contains_key("HUSH_PASSPHRASE"));
        assert!(!env.contains_key("HTTPS_PROXY"));
        assert_eq!(env[ACTIVE_VAR], "1");
    }
}
