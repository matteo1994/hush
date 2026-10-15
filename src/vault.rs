use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use age::secrecy::SecretString;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Binding {
    pub host: String,
    #[serde(default)]
    pub env: Option<String>,
    #[serde(default = "default_header")]
    pub header: String,
    #[serde(default = "default_format")]
    pub format: String,
    /// Also swap over plain HTTP to a non-loopback host, where the real value
    /// crosses the network unencrypted.
    #[serde(default)]
    pub allow_http: bool,
}

fn default_header() -> String {
    "Authorization".to_string()
}

fn default_format() -> String {
    "Bearer {value}".to_string()
}

impl Binding {
    pub fn new(
        host: String,
        env: Option<String>,
        header: Option<String>,
        format: Option<String>,
        allow_http: bool,
    ) -> Self {
        Binding {
            host,
            env,
            header: header.unwrap_or_else(default_header),
            format: format.unwrap_or_else(default_format),
            allow_http,
        }
    }
}

impl Binding {
    /// The bound host's name, and the port `--host` named, if any.
    pub fn host_and_port(&self) -> (String, Option<u16>) {
        split_host(&self.host)
    }
}

/// Splits `--host` into a name and an optional port: `api.example.com`,
/// `localhost:3000`, `[::1]:3000`. A bare IPv6 address has no port. An
/// unparsable port stays part of the name, which then matches nothing.
pub fn split_host(host: &str) -> (String, Option<u16>) {
    if let Some(rest) = host.strip_prefix('[')
        && let Some((name, after)) = rest.split_once(']')
    {
        let port = after.strip_prefix(':').and_then(|p| p.parse().ok());
        return (name.to_string(), port);
    }
    match host.split_once(':') {
        Some((name, port)) if !port.contains(':') => match port.parse() {
            Ok(port) => (name.to_string(), Some(port)),
            Err(_) => (host.to_string(), None),
        },
        _ => (host.to_string(), None),
    }
}

/// Whether `name` always means this machine. A name that only resolves to
/// it, through `/etc/hosts` say, isn't caught here; the proxy checks the
/// address it actually connected to.
pub fn is_loopback_name(name: &str) -> bool {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    name == "localhost"
        || name.ends_with(".localhost")
        || name
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.to_canonical().is_loopback())
}

/// Refuses a `--host` that can never be used: a port that isn't one, or a
/// loopback host without a port. On this machine every port is open to the
/// child, so the key is only ever sent to a loopback server on the port its
/// binding names.
pub fn check_host(host: &str) -> Result<()> {
    if host.is_empty() {
        bail!("--host is empty");
    }
    let (name, port) = split_host(host);
    if name.contains(':') && !name.contains("::") && name.parse::<std::net::IpAddr>().is_err() {
        bail!("--host {host}: not a valid port");
    }
    if port.is_none() && is_loopback_name(&name) {
        bail!(
            "--host {host} needs a port, such as {}:3000: any program on this machine can listen on its other ports",
            if name.contains(':') {
                format!("[{name}]")
            } else {
                name
            }
        );
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretEntry {
    pub value: String,
    #[serde(default)]
    pub bindings: Vec<Binding>,
}

impl SecretEntry {
    /// Adds a binding, refusing a second one for the same env: `find_binding`
    /// only ever uses the first, so the new one would be silently ignored.
    pub fn add_binding(&mut self, binding: Binding) -> Result<()> {
        if let Some(existing) = self.bindings.iter().find(|b| b.env == binding.env) {
            bail!(
                "already bound to {} for env {}; to change that, `hush secret rm` the secret and add it again",
                existing.host,
                binding.env.as_deref().unwrap_or("default")
            );
        }
        self.bindings.push(binding);
        Ok(())
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Vault {
    pub secrets: HashMap<String, SecretEntry>,
}

impl Vault {
    pub fn new() -> Self {
        Vault {
            secrets: HashMap::new(),
        }
    }

    pub fn find_binding<'a>(
        &'a self,
        name: &str,
        env: Option<&str>,
    ) -> Option<(&'a SecretEntry, &'a Binding)> {
        let entry = self.secrets.get(name)?;
        // Prefer an exact env match, then fall back to an unscoped binding.
        let exact = entry
            .bindings
            .iter()
            .find(|b| b.env.as_deref() == env && env.is_some());
        let unscoped = entry.bindings.iter().find(|b| b.env.is_none());
        let binding = exact.or(unscoped)?;
        Some((entry, binding))
    }
}

pub fn config_dir() -> Result<PathBuf> {
    let base = std::env::home_dir().context("could not determine home directory")?;
    Ok(base.join(".config").join("hush"))
}

pub fn vault_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("vault.age"))
}

/// Names (never values) of secrets every `hush run` should get, wherever
/// it's started; same format as `.env`.
pub fn global_env_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("global.env"))
}

/// Parent of the per-`hush run` directories holding that run's CA files.
pub fn runs_dir() -> Result<PathBuf> {
    Ok(config_dir()?.join("runs"))
}

/// Held across a load-modify-save, so two `hush secret` commands running at
/// once can't each save over the other's change. Released when dropped.
pub struct VaultLock {
    _file: fs::File,
}

/// Takes the vault lock, waiting for another hush command that holds it. The
/// lock is a separate file because saving replaces `vault.age` by rename.
pub fn lock_vault() -> Result<VaultLock> {
    let path = config_dir()?.join("vault.lock");
    if let Some(lock) = try_lock_at(&path)? {
        return Ok(lock);
    }
    eprintln!("hush: waiting for another hush command to finish changing the vault");
    let file = open_lock_file(&path)?;
    file.lock()
        .with_context(|| format!("locking {}", path.display()))?;
    Ok(VaultLock { _file: file })
}

fn try_lock_at(path: &Path) -> Result<Option<VaultLock>> {
    let file = open_lock_file(path)?;
    match file.try_lock() {
        Ok(()) => Ok(Some(VaultLock { _file: file })),
        Err(fs::TryLockError::WouldBlock) => Ok(None),
        Err(fs::TryLockError::Error(e)) => {
            Err(e).with_context(|| format!("locking {}", path.display()))
        }
    }
}

fn open_lock_file(path: &Path) -> Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))
}

pub fn vault_exists() -> Result<bool> {
    Ok(vault_path()?.exists())
}

pub fn init_vault(passphrase: &str) -> Result<()> {
    let dir = config_dir()?;
    fs::create_dir_all(&dir)?;
    set_private_mode(&dir)?;
    let _lock = lock_vault()?;

    let path = vault_path()?;
    if path.exists() {
        bail!("vault already exists at {}", path.display());
    }

    let vault = Vault::new();
    save_vault(&vault, passphrase)?;
    Ok(())
}

pub fn load_vault(passphrase: &str) -> Result<Vault> {
    let path = vault_path()?;
    let encrypted =
        fs::read(&path).with_context(|| format!("reading vault at {}", path.display()))?;

    let decryptor = age::Decryptor::new(&encrypted[..])?;
    let identity = age::scrypt::Identity::new(SecretString::from(passphrase.to_string()));

    let mut decrypted = Vec::new();
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|_| anyhow::anyhow!("wrong passphrase or corrupted vault"))?;
    reader.read_to_end(&mut decrypted)?;

    let vault: Vault =
        serde_json::from_slice(&decrypted).context("vault contents are not valid")?;
    Ok(vault)
}

pub fn save_vault(vault: &Vault, passphrase: &str) -> Result<()> {
    let plaintext = serde_json::to_vec(vault)?;
    let secret = SecretString::from(passphrase.to_string());
    let encryptor = age::Encryptor::with_user_passphrase(secret);

    let mut encrypted = Vec::new();
    let mut writer = encryptor.wrap_output(&mut encrypted)?;
    writer.write_all(&plaintext)?;
    writer.finish()?;

    let path = vault_path()?;
    let tmp_path = path.with_extension("age.tmp");
    fs::write(&tmp_path, &encrypted)?;
    set_owner_only(&tmp_path)?;
    fs::rename(&tmp_path, &path)?;
    Ok(())
}

#[cfg(unix)]
pub fn set_private_mode(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(unix)]
fn set_owner_only(path: &PathBuf) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_a_host_and_its_port() {
        assert_eq!(
            split_host("api.example.com"),
            ("api.example.com".into(), None)
        );
        assert_eq!(
            split_host("localhost:3000"),
            ("localhost".into(), Some(3000))
        );
        assert_eq!(split_host("[::1]:3000"), ("::1".into(), Some(3000)));
        assert_eq!(split_host("[::1]"), ("::1".into(), None));
        assert_eq!(split_host("::1"), ("::1".into(), None));
        assert_eq!(split_host("localhost:x"), ("localhost:x".into(), None));
    }

    #[test]
    fn loopback_hosts_need_a_port() {
        for host in [
            "localhost",
            "LOCALHOST.",
            "app.localhost",
            "127.0.0.1",
            "127.1.2.3",
            "::1",
            "[::1]",
        ] {
            assert!(check_host(host).is_err(), "{host}");
        }
        for host in [
            "localhost:3000",
            "127.0.0.1:8080",
            "[::1]:3000",
            "api.example.com",
            "10.0.0.5",
            "api.example.com:8443",
        ] {
            assert!(check_host(host).is_ok(), "{host}");
        }
        assert!(check_host("localhost:x").is_err());
        assert!(check_host("").is_err());
    }

    #[test]
    fn add_binding_refuses_a_second_binding_for_the_same_env() {
        let bind = |host: &str, env: Option<&str>| {
            Binding::new(host.into(), env.map(Into::into), None, None, false)
        };
        let mut entry = SecretEntry {
            value: "REAL".into(),
            bindings: vec![bind("api.example.com", None)],
        };
        entry
            .add_binding(bind("staging.example.com", Some("staging")))
            .unwrap();

        let err = entry
            .add_binding(bind("evil.example.com", None))
            .unwrap_err();
        assert!(
            err.to_string().contains("api.example.com for env default"),
            "{err}"
        );
        let err = entry
            .add_binding(bind("evil.example.com", Some("staging")))
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("staging.example.com for env staging"),
            "{err}"
        );

        let hosts: Vec<_> = entry.bindings.iter().map(|b| b.host.as_str()).collect();
        assert_eq!(hosts, ["api.example.com", "staging.example.com"]);
    }

    #[test]
    fn vault_lock_is_exclusive_until_dropped() {
        let path = std::env::temp_dir().join(format!("hush-lock-test-{}", std::process::id()));
        let first = try_lock_at(&path).unwrap().expect("free lock");
        assert!(try_lock_at(&path).unwrap().is_none());
        drop(first);
        // Wait rather than try: a child another test is spawning can hold
        // the descriptor, and so the lock, until its exec closes it.
        open_lock_file(&path).unwrap().lock().unwrap();
        fs::remove_file(&path).unwrap();
    }
}
