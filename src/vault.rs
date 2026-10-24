use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use age::secrecy::SecretString;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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

/// Whether a binding to this machine can never be used. On this machine the
/// child can listen on any port, and on the other address family of a port
/// (`localhost` is both `127.0.0.1` and `::1`), so the proxy only sends a key
/// to the exact socket a binding names: a loopback address and a port.
pub fn unusable_loopback(name: &str, port: Option<u16>) -> bool {
    is_loopback_name(name) && (port.is_none() || name.parse::<std::net::IpAddr>().is_err())
}

/// Refuses a `--host` that can never be used: a port that isn't one, or a
/// loopback host that isn't an address with a port.
pub fn check_host(host: &str) -> Result<()> {
    if host.is_empty() {
        bail!("--host is empty");
    }
    let (name, port) = split_host(host);
    if name.contains(':') && !name.contains("::") && name.parse::<std::net::IpAddr>().is_err() {
        bail!("--host {host}: not a valid port");
    }
    if unusable_loopback(&name, port) {
        bail!(
            "--host {host}: a server on this machine needs its address and port, such as 127.0.0.1:{0} or [::1]:{0}, whichever it listens on; any program here can listen on another port or address family",
            port.unwrap_or(3000)
        );
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretEntry {
    pub value: String,
    #[serde(default)]
    pub bindings: Vec<Binding>,
    /// Unix seconds when the value was last set. Absent in a vault written
    /// before rotation was recorded; `secret ls` shows that as unknown
    /// rather than as ancient.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotated_at: Option<i64>,
    /// How long the value may be used, in seconds, before `hush run` warns.
    /// Absent means no limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_age_secs: Option<u64>,
}

impl SecretEntry {
    /// Adds a binding, refusing a second one for the same env: `find_binding`
    /// only ever uses the first, so the new one would be silently ignored.
    pub fn add_binding(&mut self, binding: Binding) -> Result<()> {
        if let Some(existing) = self.bindings.iter().find(|b| b.env == binding.env) {
            bail!(
                "already bound to {} for env {}; to change it, `hush secret unbind` that host and `hush secret bind` the new one",
                existing.host,
                binding.env.as_deref().unwrap_or("default")
            );
        }
        self.bindings.push(binding);
        Ok(())
    }

    /// Drops the one binding for `host`. Without `env`, a host bound for a
    /// single env is that one; a host bound for several needs `--env`, so
    /// the wrong one isn't the one that goes. `default`, the name errors and
    /// `add_binding` give a binding without an env, picks that one, unless an
    /// env is really called that.
    pub fn remove_binding(&mut self, host: &str, env: Option<&str>) -> Result<()> {
        let host_matches = |b: &Binding| b.host.eq_ignore_ascii_case(host);
        let select = |env_matches: &dyn Fn(&Binding) -> bool| -> Vec<usize> {
            self.bindings
                .iter()
                .enumerate()
                .filter(|(_, b)| host_matches(b) && env_matches(b))
                .map(|(i, _)| i)
                .collect()
        };
        let mut indexes = select(&|b| env.is_none_or(|e| b.env.as_deref() == Some(e)));
        if indexes.is_empty() && env == Some("default") {
            indexes = select(&|b| b.env.is_none());
        }
        match indexes.as_slice() {
            [index] => {
                self.bindings.remove(*index);
                Ok(())
            }
            [] => {
                let others: Vec<&str> = self
                    .bindings
                    .iter()
                    .filter(|b| host_matches(b))
                    .map(|b| b.env.as_deref().unwrap_or("default"))
                    .collect();
                match env {
                    Some(env) if !others.is_empty() => {
                        bail!(
                            "no binding for host {host} and env {env}; that host is bound for env {}",
                            others.join(", ")
                        )
                    }
                    _ => bail!("no binding for host {host}"),
                }
            }
            _ => {
                let envs: Vec<&str> = indexes
                    .iter()
                    .map(|i| self.bindings[*i].env.as_deref().unwrap_or("default"))
                    .collect();
                bail!(
                    "host {host} is bound for more than one env ({}); pass --env, with `default` for the binding without one",
                    envs.join(", ")
                )
            }
        }
    }

    /// One line for `secret ls`. It names ages, never the value.
    pub fn age_label(&self, now: i64) -> String {
        let Some(rotated) = self.rotated_at else {
            return "age unknown".to_string();
        };
        let age = age_secs(rotated, now);
        let mut line = format!("rotated {}", format_age(age));
        if let Some(max) = self.max_age_secs {
            if age >= max {
                line.push_str(&format!(", overdue (max age {})", format_span(max)));
            } else {
                line.push_str(&format!(", max age {}", format_span(max)));
            }
        }
        line
    }

    /// Set when this secret is past its max age. The text names `name`, never the value.
    pub fn overdue_warning(&self, name: &str, now: i64) -> Option<String> {
        let max = self.max_age_secs?;
        let rotated = self.rotated_at?;
        let age = age_secs(rotated, now);
        if age < max {
            return None;
        }
        Some(format!(
            "{name} is overdue for rotation ({} old, max age {})",
            format_span_floored(age),
            format_span(max)
        ))
    }
}

fn age_secs(rotated_at: i64, now: i64) -> u64 {
    u64::try_from(now.saturating_sub(rotated_at).max(0)).unwrap_or(u64::MAX)
}

/// `90d`, `12h`, `30m`, `45s`, `2w`. Zero is refused: a max age of nothing
/// would warn on every run.
pub fn parse_duration(text: &str) -> Result<u64> {
    let text = text.trim();
    let split = text
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(text.len());
    let (num, unit) = text.split_at(split);
    if num.is_empty() || unit.is_empty() {
        bail!("duration {text:?}: use a number and a unit, such as 90d, 12h or 30m");
    }
    let n: u64 = num
        .parse()
        .map_err(|_| anyhow::anyhow!("duration {text:?}: number is too large"))?;
    if n == 0 {
        bail!("duration {text:?}: must be at least 1");
    }
    let factor: u64 = match unit.to_ascii_lowercase().as_str() {
        "s" => 1,
        "m" => 60,
        "h" => 60 * 60,
        "d" => 60 * 60 * 24,
        "w" => 60 * 60 * 24 * 7,
        _ => bail!("duration {text:?}: unit must be s, m, h, d or w"),
    };
    n.checked_mul(factor)
        .ok_or_else(|| anyhow::anyhow!("duration {text:?}: too long"))
}

pub fn now_unix() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_secs()).ok())
        .unwrap_or(0)
}

fn format_age(secs: u64) -> String {
    if secs < 60 {
        "just now".to_string()
    } else {
        format!("{} ago", format_span_floored(secs))
    }
}

/// The configured span, which divides evenly into the unit it was given as.
fn format_span(secs: u64) -> String {
    if secs.is_multiple_of(86400) {
        format!("{}d", secs / 86400)
    } else if secs.is_multiple_of(3600) {
        format!("{}h", secs / 3600)
    } else if secs.is_multiple_of(60) {
        format!("{}m", secs / 60)
    } else {
        format!("{secs}s")
    }
}

fn format_span_floored(secs: u64) -> String {
    if secs >= 86400 {
        format!("{}d", secs / 86400)
    } else if secs >= 3600 {
        format!("{}h", secs / 3600)
    } else if secs >= 60 {
        format!("{}m", secs / 60)
    } else {
        format!("{secs}s")
    }
}

/// A named set of entries, so the same name (`OPENAI_API_KEY`, say) can hold
/// a different key and endpoint per project.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub secrets: HashMap<String, SecretEntry>,
}

/// Every vault type refuses fields it doesn't know: a vault written by a
/// newer hush must fail to load here rather than lose those fields on the
/// next save. (hush 0.1.16 and earlier ignore them, so they drop profiles.)
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Vault {
    /// The unprofiled entries, used by every profile that doesn't have its
    /// own entry for a name.
    pub secrets: HashMap<String, SecretEntry>,
    /// Left out when empty, so a vault without profiles is written exactly
    /// as before profiles existed. A vault written before them has none.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub profiles: HashMap<String, Profile>,
    /// Project directory → the profile runs started in it use (`hush profile
    /// use`). Kept in the vault rather than the project, so changing which
    /// profile a project gets takes the passphrase, like any other change.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub directories: BTreeMap<String, String>,
}

impl Vault {
    pub fn new() -> Self {
        Vault::default()
    }

    /// `name`'s entry in `profile`, or else its unprofiled entry, so a key
    /// every project shares needn't be copied into each profile.
    pub fn entry(&self, name: &str, profile: Option<&str>) -> Option<&SecretEntry> {
        profile
            .and_then(|p| self.profiles.get(p))
            .and_then(|p| p.secrets.get(name))
            .or_else(|| self.secrets.get(name))
    }

    /// The binding for `env` in `name`'s entry (see `entry`). A profile's
    /// entry replaces the unprofiled one whole: when it has no binding for
    /// `env`, the unprofiled entry's bindings aren't tried, since they go
    /// with a different value.
    pub fn find_binding<'a>(
        &'a self,
        name: &str,
        profile: Option<&str>,
        env: Option<&str>,
    ) -> Option<(&'a SecretEntry, &'a Binding)> {
        let entry = self.entry(name, profile)?;
        // Prefer an exact env match, then fall back to an unscoped binding.
        let exact = entry
            .bindings
            .iter()
            .find(|b| b.env.as_deref() == env && env.is_some());
        let unscoped = entry.bindings.iter().find(|b| b.env.is_none());
        let binding = exact.or(unscoped)?;
        Some((entry, binding))
    }

    /// The entries `--profile` names, or the unprofiled ones without it.
    /// `None` for a profile that doesn't exist.
    pub fn secrets_in(&self, profile: Option<&str>) -> Option<&HashMap<String, SecretEntry>> {
        match profile {
            Some(p) => self.profiles.get(p).map(|p| &p.secrets),
            None => Some(&self.secrets),
        }
    }

    pub fn secrets_in_mut(
        &mut self,
        profile: Option<&str>,
    ) -> Option<&mut HashMap<String, SecretEntry>> {
        match profile {
            Some(p) => self.profiles.get_mut(p).map(|p| &mut p.secrets),
            None => Some(&mut self.secrets),
        }
    }

    /// Like `secrets_in_mut`, creating the profile if it doesn't exist.
    pub fn secrets_in_or_new(
        &mut self,
        profile: Option<&str>,
    ) -> &mut HashMap<String, SecretEntry> {
        match profile {
            Some(p) => &mut self.profiles.entry(p.to_string()).or_default().secrets,
            None => &mut self.secrets,
        }
    }

    /// Removes `name` from `profile` (or the unprofiled entries), and the
    /// profile with it once it holds nothing, so `ls` doesn't list it.
    pub fn remove(&mut self, name: &str, profile: Option<&str>) -> Option<SecretEntry> {
        let removed = self.secrets_in_mut(profile)?.remove(name);
        if let Some(p) = profile
            && self.profiles.get(p).is_some_and(|p| p.secrets.is_empty())
        {
            self.profiles.remove(p);
        }
        removed
    }

    /// The mapped directory nearest `dir` (itself or an ancestor), and its
    /// profile. `dir` must be canonical, as the mapped ones are.
    pub fn mapped_profile(&self, dir: &Path) -> Option<(&str, &str)> {
        dir.ancestors().find_map(|d| {
            self.directories
                .get_key_value(d.to_str()?)
                .map(|(d, p)| (d.as_str(), p.as_str()))
        })
    }
}

/// Refuses a `--profile` name that would be awkward on a command line or in
/// `secret ls` output: it starts with a letter or digit (not `-`, `.` or
/// `..`), then letters, digits, `-`, `_` and `.`.
pub fn check_profile(name: &str) -> Result<()> {
    if !name.starts_with(|c: char| c.is_ascii_alphanumeric())
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        bail!(
            "--profile {name:?}: start with a letter or digit, then use letters, digits, '-', '_' and '.'"
        );
    }
    Ok(())
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

    let vault: Vault = serde_json::from_slice(&decrypted)
        .context("vault contents are not valid, or were written by a newer hush")?;
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
            "localhost:3000",
            "app.localhost:3000",
        ] {
            assert!(check_host(host).is_err(), "{host}");
        }
        for host in [
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
            rotated_at: None,
            max_age_secs: None,
        };
        entry
            .add_binding(bind("staging.example.com", Some("staging")))
            .unwrap();

        let err = entry
            .add_binding(bind("evil.example.com", None))
            .unwrap_err();
        assert!(
            err.to_string().contains("api.example.com for env default")
                && err.to_string().contains("hush secret unbind"),
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

    fn entry(value: &str, bindings: &[(&str, Option<&str>)]) -> SecretEntry {
        SecretEntry {
            value: value.into(),
            bindings: bindings
                .iter()
                .map(|&(host, env)| {
                    Binding::new(host.into(), env.map(Into::into), None, None, false)
                })
                .collect(),
            rotated_at: None,
            max_age_secs: None,
        }
    }

    #[test]
    fn a_vault_from_before_profiles_loads_and_is_written_the_same() {
        let old = r#"{"secrets":{"OPENAI_API_KEY":{"value":"REAL","bindings":[{"host":"api.openai.com","env":null,"header":"Authorization","format":"Bearer {value}","allow_http":false}]}}}"#;
        let vault: Vault = serde_json::from_str(old).unwrap();
        assert!(vault.profiles.is_empty());
        assert_eq!(vault.secrets["OPENAI_API_KEY"].value, "REAL");
        assert_eq!(vault.secrets["OPENAI_API_KEY"].rotated_at, None);
        assert_eq!(vault.secrets["OPENAI_API_KEY"].max_age_secs, None);
        assert_eq!(serde_json::to_string(&vault).unwrap(), old);
    }

    #[test]
    fn a_vault_with_fields_this_hush_does_not_know_is_refused() {
        for json in [
            r#"{"secrets":{},"future":1}"#,
            r#"{"secrets":{"K":{"value":"V","bindings":[],"future":1}}}"#,
            r#"{"secrets":{"K":{"value":"V","bindings":[{"host":"h","future":1}]}}}"#,
            r#"{"secrets":{},"profiles":{"p":{"secrets":{},"future":1}}}"#,
        ] {
            assert!(serde_json::from_str::<Vault>(json).is_err(), "{json}");
        }
    }

    #[test]
    fn profiles_survive_a_save_and_load() {
        let mut vault = Vault::new();
        vault
            .profiles
            .entry("acme".into())
            .or_default()
            .secrets
            .insert(
                "OPENAI_API_KEY".into(),
                entry("ACME", &[("acme.openai.azure.com", None)]),
            );
        let json = serde_json::to_vec(&vault).unwrap();
        let back: Vault = serde_json::from_slice(&json).unwrap();
        let acme = &back.profiles["acme"].secrets["OPENAI_API_KEY"];
        assert_eq!(acme.value, "ACME");
        assert_eq!(acme.bindings[0].host, "acme.openai.azure.com");
    }

    #[test]
    fn a_profile_entry_wins_and_unprofiled_entries_fill_in() {
        let mut vault = Vault::new();
        vault.secrets.insert(
            "OPENAI_API_KEY".into(),
            entry(
                "SHARED",
                &[
                    ("api.openai.com", None),
                    ("staging.openai.com", Some("staging")),
                ],
            ),
        );
        vault.secrets.insert(
            "GITHUB_KEY".into(),
            entry("GH", &[("api.github.com", None)]),
        );
        vault
            .profiles
            .entry("acme".into())
            .or_default()
            .secrets
            .insert(
                "OPENAI_API_KEY".into(),
                entry("ACME", &[("acme.openai.azure.com", None)]),
            );
        let found = |name, profile, env| {
            vault
                .find_binding(name, profile, env)
                .map(|(e, b)| (e.value.as_str(), b.host.as_str()))
        };

        assert_eq!(
            found("OPENAI_API_KEY", Some("acme"), None),
            Some(("ACME", "acme.openai.azure.com"))
        );
        // A name the profile doesn't have, and a profile that doesn't exist.
        assert_eq!(
            found("GITHUB_KEY", Some("acme"), None),
            Some(("GH", "api.github.com"))
        );
        assert_eq!(
            found("OPENAI_API_KEY", Some("beta"), None),
            Some(("SHARED", "api.openai.com"))
        );
        assert_eq!(
            found("OPENAI_API_KEY", None, Some("staging")),
            Some(("SHARED", "staging.openai.com"))
        );
        // The profile's entry has no staging binding, but its unscoped one
        // still applies; the shared entry's staging binding goes with the
        // shared value, so it isn't used for acme.
        assert_eq!(
            found("OPENAI_API_KEY", Some("acme"), Some("staging")),
            Some(("ACME", "acme.openai.azure.com"))
        );
    }

    #[test]
    fn a_profile_entry_without_a_matching_binding_does_not_fall_back() {
        let mut vault = Vault::new();
        vault
            .secrets
            .insert("KEY".into(), entry("SHARED", &[("api.example.com", None)]));
        vault
            .profiles
            .entry("acme".into())
            .or_default()
            .secrets
            .insert(
                "KEY".into(),
                entry("ACME", &[("acme.example.com", Some("prod"))]),
            );
        assert!(vault.find_binding("KEY", Some("acme"), None).is_none());
    }

    #[test]
    fn the_nearest_mapped_directory_gives_the_profile() {
        let mut vault = Vault::new();
        vault.directories.insert("/w/acme".into(), "acme".into());
        vault
            .directories
            .insert("/w/acme/vendor/x".into(), "x".into());
        let mapped = |dir: &str| vault.mapped_profile(Path::new(dir));
        assert_eq!(mapped("/w/acme"), Some(("/w/acme", "acme")));
        assert_eq!(mapped("/w/acme/src/lib"), Some(("/w/acme", "acme")));
        assert_eq!(
            mapped("/w/acme/vendor/x/y"),
            Some(("/w/acme/vendor/x", "x"))
        );
        // Whole path components only.
        assert_eq!(mapped("/w/acme-old"), None);
        assert_eq!(mapped("/w"), None);

        let json = serde_json::to_vec(&vault).unwrap();
        let back: Vault = serde_json::from_slice(&json).unwrap();
        assert_eq!(back.directories, vault.directories);
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

    #[test]
    fn rotation_fields_load_and_an_old_secret_has_no_age() {
        let json = r#"{"secrets":{"K":{"value":"super-secret-value","bindings":[],"rotated_at":1000,"max_age_secs":86400}}}"#;
        let vault: Vault = serde_json::from_str(json).unwrap();
        let stored = &vault.secrets["K"];
        assert_eq!(stored.rotated_at, Some(1000));
        assert_eq!(stored.max_age_secs, Some(86400));
        assert_eq!(
            stored.age_label(1000 + 3 * 86400),
            "rotated 3d ago, overdue (max age 1d)"
        );
        let warning = stored.overdue_warning("K", 1000 + 3 * 86400).unwrap();
        assert!(warning.contains("K is overdue"), "{warning}");
        assert!(!warning.contains("super-secret-value"), "{warning}");
        assert!(stored.overdue_warning("K", 1000 + 3600).is_none());

        let unknown = entry("V", &[]);
        assert_eq!(unknown.age_label(1_700_000_000), "age unknown");
        assert!(unknown.overdue_warning("V", 1_700_000_000).is_none());
    }

    #[test]
    fn durations_use_a_unit_and_refuse_zero() {
        assert_eq!(parse_duration("90d").unwrap(), 90 * 86400);
        assert_eq!(parse_duration("12h").unwrap(), 12 * 3600);
        assert_eq!(parse_duration("30m").unwrap(), 30 * 60);
        assert_eq!(parse_duration("45s").unwrap(), 45);
        assert_eq!(parse_duration("2w").unwrap(), 14 * 86400);
        assert_eq!(parse_duration(" 2D ").unwrap(), 2 * 86400);
        for bad in ["", "90", "0d", "0", "d", "-1d", "1x", "999999999999999999d"] {
            assert!(parse_duration(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn unbind_removes_one_host_and_asks_when_several_envs_share_it() {
        let bind = |host: &str, env: Option<&str>| {
            Binding::new(host.into(), env.map(Into::into), None, None, false)
        };
        let mut entry = entry("super-secret-value", &[]);
        entry.bindings = vec![
            bind("api.example.com", None),
            bind("api.example.com", Some("staging")),
            bind("other.example.com", None),
        ];
        let err = entry.remove_binding("API.example.com", None).unwrap_err();
        assert!(err.to_string().contains("pass --env"), "{err}");
        assert!(!err.to_string().contains("super-secret-value"), "{err}");
        assert_eq!(entry.bindings.len(), 3);

        // `default` is how the binding without an env is shown, and how it
        // is picked out from the others on the same host.
        let mut unscoped = entry.clone();
        unscoped
            .remove_binding("api.example.com", Some("default"))
            .unwrap();
        let envs: Vec<_> = unscoped.bindings.iter().map(|b| b.env.as_deref()).collect();
        assert_eq!(envs, [Some("staging"), None]);

        entry
            .remove_binding("api.example.com", Some("staging"))
            .unwrap();
        let hosts: Vec<_> = entry
            .bindings
            .iter()
            .map(|b| (b.host.as_str(), b.env.as_deref()))
            .collect();
        assert_eq!(
            hosts,
            [("api.example.com", None), ("other.example.com", None),]
        );

        let err = entry
            .remove_binding("api.example.com", Some("nope"))
            .unwrap_err();
        assert!(err.to_string().contains("env default"), "{err}");
        entry.remove_binding("other.example.com", None).unwrap();
        entry.remove_binding("api.example.com", None).unwrap();
        assert!(entry.bindings.is_empty());
        assert!(entry.remove_binding("api.example.com", None).is_err());
    }
}
