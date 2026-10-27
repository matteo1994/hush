//! The vault passphrase in the login keychain, so a `hush run` started with
//! no terminal, such as an MCP server under the Claude desktop app, can open
//! the vault after Touch ID or the login password instead of a typed prompt.
//!
//! The item is a plain login-keychain password: a Touch ID-gated item needs
//! a provisioning profile, which an unsigned or ad-hoc signed binary can't
//! have. macOS lets the binary that created the item read it without asking,
//! and asks for the login password when any other program, or a rebuilt
//! hush, tries. So the item is only as safe as that binary, and `store`
//! refuses a hush without the hardened runtime, which would load a
//! `DYLD_INSERT_LIBRARIES` library able to read it. The Touch ID check in
//! `unlock` runs inside hush, so it only keeps an unattended `hush run` from
//! opening the vault silently; the access list is what keeps other programs
//! out. Only `hush run` uses the item: every vault change still takes the
//! typed passphrase, so a child that runs hush itself can't rebind a key.

use std::sync::mpsc;

use anyhow::{Result, anyhow, bail};
use block2::RcBlock;
use objc2::runtime::Bool;
use objc2_foundation::{NSError, NSString};
use objc2_local_authentication::{LAContext, LAError, LAPolicy};
use security_framework::item::{ItemClass, ItemSearchOptions};
use security_framework::os::macos::keychain::SecKeychain;

use crate::{harden, vault};

const SERVICE: &str = "hush";
/// errSecItemNotFound.
const NOT_FOUND: i32 = -25300;
/// How long `unlock` waits for Touch ID before falling back.
const ANSWER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// One item per vault, named by the vault's path, so a vault under another
/// `HOME`, such as a test's, never reads this one's passphrase.
fn account() -> Result<String> {
    Ok(vault::vault_path()?.display().to_string())
}

/// The user's login keychain, found from the account database rather than
/// `HOME`: the Security framework looks for the default keychain under
/// `HOME`, so with another `HOME` it fails, or waits on a dialog.
fn login_keychain() -> Result<SecKeychain> {
    // SAFETY: getpwuid returns a pointer to static storage or null; the
    // directory is copied out before anything else can call it.
    let home = unsafe {
        let pw = libc::getpwuid(libc::getuid());
        if pw.is_null() || (*pw).pw_dir.is_null() {
            bail!("couldn't find your home directory in the account database");
        }
        std::ffi::CStr::from_ptr((*pw).pw_dir)
            .to_string_lossy()
            .into_owned()
    };
    let path = std::path::Path::new(&home).join("Library/Keychains/login.keychain-db");
    if !path.exists() {
        bail!("no login keychain at {}", path.display());
    }
    SecKeychain::open(&path).map_err(|e| anyhow!("opening {}: {e}", path.display()))
}

/// This vault's item in the login keychain.
fn search(keychain: &SecKeychain) -> Result<ItemSearchOptions> {
    let mut options = ItemSearchOptions::new();
    options
        .keychains(std::slice::from_ref(keychain))
        .class(ItemClass::generic_password())
        .service(SERVICE)
        .account(&account()?);
    Ok(options)
}

/// Whether a passphrase is saved for this vault. Reads only the item's
/// attributes, which needs no permission.
pub fn is_enabled() -> Result<bool> {
    match search(&login_keychain()?)?.load_attributes(true).search() {
        Ok(found) => Ok(!found.is_empty()),
        Err(e) if e.code() == NOT_FOUND => Ok(false),
        Err(e) => Err(anyhow!("checking the keychain: {e}")),
    }
}

/// Saves `pass`, replacing any earlier item. The old item is deleted rather
/// than updated, so the new one trusts the hush running now; an update would
/// keep the access list of the hush that created it.
pub fn store(pass: &str) -> Result<()> {
    check_hardened()?;
    remove()?;
    login_keychain()?
        .add_generic_password(SERVICE, &account()?, pass.as_bytes())
        .map_err(|e| anyhow!("saving the passphrase in the keychain: {e}"))
}

/// Refuses a hush without the hardened runtime, which could have a library
/// injected that reads the item. This asks the process about itself, so it
/// stops an honest unsigned hush, not an injected one; for that, the access
/// list trusts only the binary that saved the item.
pub fn check_hardened() -> Result<()> {
    if !harden::hardened_runtime() {
        bail!(
            "this hush isn't signed with the hardened runtime, so a library injected into it could read the keychain item; sign it first: {}",
            harden::codesign_hint()
        );
    }
    Ok(())
}

/// Removes the saved passphrase; false when there was none.
pub fn remove() -> Result<bool> {
    match search(&login_keychain()?)?.delete() {
        Ok(()) => Ok(true),
        Err(e) if e.code() == NOT_FOUND => Ok(false),
        Err(e) => Err(anyhow!("removing the passphrase from the keychain: {e}")),
    }
}

pub enum Unlocked {
    Passphrase(String),
    /// Touch ID or the password dialog was dismissed.
    Cancelled,
    /// The check or the keychain read failed, for this reason.
    Failed(String),
}

/// The saved passphrase, after Touch ID or the login password. `reason`
/// completes the system's "hush is trying to ..." line.
pub fn unlock(reason: &str) -> Unlocked {
    match confirm_owner(reason) {
        Ok(()) => {}
        Err(None) => return Unlocked::Cancelled,
        Err(Some(why)) => return Unlocked::Failed(why),
    }
    let found = login_keychain().and_then(|kc| Ok(kc.find_generic_password(SERVICE, &account()?)?));
    match found {
        Ok((pass, _)) => match String::from_utf8(pass.to_vec()) {
            Ok(pass) => Unlocked::Passphrase(pass),
            Err(_) => Unlocked::Failed("the saved passphrase isn't text".into()),
        },
        Err(e) => Unlocked::Failed(format!("reading the keychain: {e}")),
    }
}

/// Touch ID, or the login password where there is none (a closed lid, a
/// Mac without a sensor). `Err(None)` when it was dismissed.
fn confirm_owner(reason: &str) -> Result<(), Option<String>> {
    let policy = LAPolicy::DeviceOwnerAuthentication;
    // SAFETY: a fresh context, used on this thread only.
    let ctx = unsafe { LAContext::new() };
    // SAFETY: plain method calls on a live context.
    if let Err(e) = unsafe { ctx.canEvaluatePolicy_error(policy) } {
        return Err(Some(e.localizedDescription().to_string()));
    }
    let (tx, rx) = mpsc::channel();
    let reply = RcBlock::new(move |ok: Bool, err: *mut NSError| {
        // SAFETY: a non-null error is a live NSError for this call.
        let code = unsafe { err.as_ref() }.map(|e| e.code());
        let _ = tx.send((ok.as_bool(), code));
    });
    // SAFETY: the block owns everything it touches, and the reply runs once
    // on a queue of the framework's own.
    unsafe {
        ctx.evaluatePolicy_localizedReason_reply(policy, &NSString::from_str(reason), &reply)
    };
    // Nobody may be at the Mac: over SSH, or with the screen locked.
    match rx.recv_timeout(ANSWER_TIMEOUT) {
        Ok((true, _)) => Ok(()),
        Ok((false, Some(code)))
            if [
                LAError::UserCancel,
                LAError::SystemCancel,
                LAError::AppCancel,
            ]
            .iter()
            .any(|c| c.0 == code) =>
        {
            Err(None)
        }
        Ok((false, code)) => Err(Some(format!(
            "authentication failed (LAError {})",
            code.unwrap_or_default()
        ))),
        Err(mpsc::RecvTimeoutError::Timeout) => {
            // SAFETY: a plain method call on a live context; it dismisses
            // the dialog, so a late answer unlocks nothing.
            unsafe { ctx.invalidate() };
            Err(Some(format!(
                "no answer to the Touch ID prompt in {}s",
                ANSWER_TIMEOUT.as_secs()
            )))
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            Err(Some("no answer from LocalAuthentication".into()))
        }
    }
}
