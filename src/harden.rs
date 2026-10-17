//! Keeps other processes of the same user, above all a `hush run` child, out
//! of this process's memory, where the passphrase and decrypted values live.
//! A same-user process can otherwise attach a debugger (lldb works without a
//! prompt on macOS) or kill hush with a signal that dumps core.

use std::process::Command;
use std::sync::OnceLock;

/// The soft core-dump limit hush started with, for the child to get back.
static CORE_LIMIT: OnceLock<libc::rlim_t> = OnceLock::new();

/// Refuses debugger attach and core dumps for the rest of this process's
/// life. Called first thing in `main`, before anything is decrypted. A call
/// that fails only warns: hush still works, just without this protection.
pub fn process() {
    // Linux: no ptrace, /proc/<pid>/mem or core dump from the same user.
    // Reset by exec, so the child is unaffected.
    #[cfg(target_os = "linux")]
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        warn("make this process non-dumpable");
    }
    // macOS: debuggers attach through ptrace, which this refuses. Core dumps
    // need their own limit, as nothing else stops one.
    #[cfg(target_os = "macos")]
    unsafe {
        if libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) != 0 {
            warn("refuse debugger attach");
        }
        let mut limit = std::mem::zeroed::<libc::rlimit>();
        if libc::getrlimit(libc::RLIMIT_CORE, &mut limit) != 0 {
            warn("turn off core dumps");
            return;
        }
        let soft = limit.rlim_cur;
        limit.rlim_cur = 0;
        if libc::setrlimit(libc::RLIMIT_CORE, &limit) != 0 {
            warn("turn off core dumps");
            return;
        }
        CORE_LIMIT.get_or_init(|| soft);
    }
}

/// Printed before any child exists, so it can't land on a child's screen.
fn warn(what: &str) {
    eprintln!(
        "hush: warning: couldn't {what} ({}); another program of yours could read hush's memory",
        std::io::Error::last_os_error()
    );
}

/// Gives a child the core-dump limit hush started with, so the hardening
/// stays with hush.
pub fn restore_for_child(cmd: &mut Command) {
    use std::os::unix::process::CommandExt;
    let Some(&soft) = CORE_LIMIT.get() else {
        return;
    };
    // SAFETY: only getrlimit/setrlimit, which are async-signal-safe.
    unsafe {
        cmd.pre_exec(move || {
            let mut limit = std::mem::zeroed::<libc::rlimit>();
            if libc::getrlimit(libc::RLIMIT_CORE, &mut limit) == 0 {
                limit.rlim_cur = soft;
                libc::setrlimit(libc::RLIMIT_CORE, &limit);
            }
            Ok(())
        });
    }
}
