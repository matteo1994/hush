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
    /// Previous values still redacted from responses, never sent. Empty,
    /// and omitted from the JSON, when there are none, so a vault from
    /// before this still round-trips.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub retired: Vec<Retired>,
}

/// A value `secret set --keep-old` stopped sending but still redacts.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Retired {
    pub value: String,
    /// Unix seconds. Scrubbed while `now < until`, then dropped on the next save.
    pub until: i64,
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

    /// Keeps the current value for response redaction until `until`. A value
    /// equal to `new_value` is not kept twice (it is scrubbed as the live
    /// value), and an empty one is not a secret. Leaves `self.value` empty
    /// when it was retired; the caller stores the new value.
    pub fn retire_current(&mut self, new_value: &str, until: i64, now: i64) {
        self.prune_retired(now);
        self.retired.retain(|r| r.value != new_value);
        if !self.value.is_empty() && self.value != new_value {
            self.retired.push(Retired {
                value: std::mem::take(&mut self.value),
                until,
            });
        }
    }

    pub fn prune_retired(&mut self, now: i64) {
        self.retired.retain(|r| r.until > now);
    }

    /// Values a run should redact and must not send. Expired ones are omitted.
    pub fn live_retired(&self, now: i64) -> Vec<String> {
        self.retired
            .iter()
            .filter(|r| r.until > now)
            .map(|r| r.value.clone())
            .collect()
    }

    /// One `secret ls` line, or nothing. It counts values, it does not print them.
    pub fn retired_label(&self, now: i64) -> Option<String> {
        let left: Vec<u64> = self
            .retired
            .iter()
            .filter(|r| r.until > now)
            .map(|r| u64::try_from(r.until.saturating_sub(now)).unwrap_or(0))
            .collect();
        let n = left.len();
        let soonest = *left.iter().min()?;
        if n == 1 {
            Some(format!(
                "1 previous value still redacted for {}",
                format_span_floored(soonest)
            ))
        } else {
            Some(format!(
                "{n} previous values still redacted, soonest expiry {}",
                format_span_floored(soonest)
            ))
        }
    }
}

/// `7d`, `12h`, `30m`, `45s`, `2w`. Zero is refused.
pub fn parse_duration(text: &str) -> Result<u64> {
    let text = text.trim();
    let split = text
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(text.len());
    let (num, unit) = text.split_at(split);
    if num.is_empty() || unit.is_empty() {
        bail!("duration {text:?}: use a number and a unit, such as 7d, 12h or 30m");
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

/// `now` plus `secs`, saturating so a huge duration stays inside i64.
pub fn until_unix(now: i64, secs: u64) -> i64 {
    now.saturating_add(i64::try_from(secs).unwrap_or(i64::MAX))
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

    /// Drops retired values whose grace period has ended, in every profile.
    pub fn prune_retired(&mut self, now: i64) {
        for entry in self.secrets.values_mut() {
            entry.prune_retired(now);
        }
        for profile in self.profiles.values_mut() {
            for entry in profile.secrets.values_mut() {
                entry.prune_retired(now);
            }
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

    let mut vault = Vault::new();
    save_vault(&mut vault, passphrase)?;
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

pub fn save_vault(vault: &mut Vault, passphrase: &str) -> Result<()> {
    save_vault_at(vault, passphrase, now_unix())
}

/// Like `save_vault`, pruning against `now`. `secret set --keep-old` passes
/// the same instant it measured the grace period from, so the write that
/// records a short window doesn't drop it by crossing a second.
pub fn save_vault_at(vault: &mut Vault, passphrase: &str, now: i64) -> Result<()> {
    // Expired retired values are only bytes until the next write. Doing it
    // here means bind, passwd and set all drop them, not only `secret set`.
    vault.prune_retired(now);
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
            retired: Vec::new(),
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

    fn entry(value: &str, bindings: &[(&str, Option<&str>)]) -> SecretEntry {
        SecretEntry {
            value: value.into(),
            bindings: bindings
                .iter()
                .map(|&(host, env)| {
                    Binding::new(host.into(), env.map(Into::into), None, None, false)
                })
                .collect(),
            retired: Vec::new(),
        }
    }

    #[test]
    fn a_vault_from_before_profiles_loads_and_is_written_the_same() {
        let old = r#"{"secrets":{"OPENAI_API_KEY":{"value":"REAL","bindings":[{"host":"api.openai.com","env":null,"header":"Authorization","format":"Bearer {value}","allow_http":false}]}}}"#;
        let vault: Vault = serde_json::from_str(old).unwrap();
        assert!(vault.profiles.is_empty());
        assert_eq!(vault.secrets["OPENAI_API_KEY"].value, "REAL");
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
    fn retiring_keeps_previous_values_until_they_expire() {
        let mut entry = entry("A", &[("api.example.com", None)]);
        let now = 1_700_000_000;
        entry.retire_current("B", now + 100, now);
        entry.value = "B".into();
        entry.retire_current("C", now + 50, now);
        entry.value = "C".into();
        assert_eq!(entry.live_retired(now), ["A".to_string(), "B".to_string()]);

        // Rotating back to A drops A from the retired list: it is the live value.
        entry.retire_current("A", now + 80, now);
        entry.value = "A".into();
        assert_eq!(entry.live_retired(now), ["B".to_string(), "C".to_string()]);
        let label = entry.retired_label(now).unwrap();
        assert!(label.contains("2 previous values"), "{label}");
        assert!(label.contains("50s"), "{label}");
        for secret in ["A", "B", "C"] {
            assert!(!label.contains(secret), "{secret} in {label}");
        }

        entry.prune_retired(now + 50);
        // B's window ended at now+50; C's runs to now+80.
        assert_eq!(entry.live_retired(now + 50), ["C".to_string()]);
        assert!(
            entry
                .retired_label(now + 50)
                .unwrap()
                .starts_with("1 previous value")
        );
        entry.prune_retired(now + 100);
        assert!(entry.live_retired(now + 100).is_empty());
        assert!(entry.retired_label(now + 100).is_none());

        // An empty value, or a set to the same value, retires nothing.
        entry.value.clear();
        entry.retire_current("D", now + 10, now);
        entry.value = "D".into();
        entry.retire_current("D", now + 10, now);
        assert!(entry.retired.is_empty());
        assert_eq!(entry.value, "D");
    }

    #[test]
    fn retired_values_round_trip_and_an_old_vault_omits_them() {
        let old = r#"{"secrets":{"K":{"value":"V","bindings":[]}}}"#;
        let vault: Vault = serde_json::from_str(old).unwrap();
        assert!(vault.secrets["K"].retired.is_empty());
        assert_eq!(serde_json::to_string(&vault).unwrap(), old);

        let mut stored = entry("NEW", &[]);
        stored.retired.push(Retired {
            value: "OLD".into(),
            until: 99,
        });
        let mut vault = Vault::new();
        vault.secrets.insert("K".into(), stored);
        let json = serde_json::to_string(&vault).unwrap();
        let back: Vault = serde_json::from_str(&json).unwrap();
        assert_eq!(back.secrets["K"].value, "NEW");
        assert_eq!(back.secrets["K"].retired.len(), 1);
        assert_eq!(back.secrets["K"].retired[0].until, 99);
        assert_eq!(back.secrets["K"].retired[0].value, "OLD");

        let bad = r#"{"secrets":{"K":{"value":"V","bindings":[],"retired":[{"value":"O","until":1,"extra":1}]}}}"#;
        assert!(serde_json::from_str::<Vault>(bad).is_err(), "{bad}");
    }

    #[test]
    fn expired_retired_values_leave_the_json_a_save_would_write() {
        let mut vault = Vault::new();
        let mut stored = entry("NEW", &[("api.example.com", None)]);
        stored.retired.push(Retired {
            value: "GONE".into(),
            until: 10,
        });
        stored.retired.push(Retired {
            value: "KEPT".into(),
            until: 100,
        });
        vault
            .profiles
            .entry("acme".into())
            .or_default()
            .secrets
            .insert("OTHER".into(), {
                let mut e = entry("P", &[]);
                e.retired.push(Retired {
                    value: "PROFILE-OLD".into(),
                    until: 10,
                });
                e
            });
        vault.secrets.insert("K".into(), stored);
        // The same prune `save_vault` runs before it encrypts.
        vault.prune_retired(50);
        let json = serde_json::to_string(&vault).unwrap();
        assert!(!json.contains("GONE"), "{json}");
        assert!(!json.contains("PROFILE-OLD"), "{json}");
        assert!(json.contains("KEPT"), "{json}");
        assert!(vault.profiles["acme"].secrets["OTHER"].retired.is_empty());
    }

    #[test]
    fn durations_use_a_unit_and_refuse_zero() {
        assert_eq!(parse_duration("7d").unwrap(), 7 * 86400);
        assert_eq!(parse_duration(" 12H ").unwrap(), 12 * 3600);
        assert_eq!(parse_duration("2w").unwrap(), 14 * 86400);
        assert_eq!(parse_duration("30m").unwrap(), 1800);
        assert_eq!(parse_duration("45s").unwrap(), 45);
        for bad in ["0d", "0", "7", "d", "1x", "9999999999999999999d", ""] {
            let err = parse_duration(bad).unwrap_err().to_string();
            assert!(!err.is_empty(), "{bad}");
            assert!(!err.contains("secret"), "{err}");
        }
        assert_eq!(until_unix(10, 5), 15);
        assert_eq!(until_unix(i64::MAX, 5), i64::MAX);
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
