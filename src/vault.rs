use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretEntry {
    pub value: String,
    #[serde(default)]
    pub bindings: Vec<Binding>,
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

pub fn vault_exists() -> Result<bool> {
    Ok(vault_path()?.exists())
}

pub fn init_vault(passphrase: &str) -> Result<()> {
    let dir = config_dir()?;
    fs::create_dir_all(&dir)?;
    set_private_mode(&dir)?;

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
