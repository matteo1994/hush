//! Keeps other processes of the same user, above all a `hush run` child, out
//! of this process's memory, where the passphrase and decrypted values live.
//! A same-user process can otherwise attach a debugger (lldb works without a
//! prompt on macOS) or kill hush with a signal that dumps core.

use std::process::Command;
use std::sync::OnceLock;

/// The soft core-dump limit hush started with, for the child to get back.
static CORE_LIMIT: OnceLock<libc::rlim_t> = OnceLock::new();

/// Refuses debugger attach and core dumps for the rest of this process's
/// life. Called first thing in `main`, before anything is decrypted.
pub fn process() {
    // Linux: no ptrace, /proc/<pid>/mem or core dump from the same user.
    // Reset by exec, so the child is unaffected.
    #[cfg(target_os = "linux")]
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
    // macOS: debuggers attach through ptrace, which this refuses. Core dumps
    // need their own limit, as nothing else stops one.
    #[cfg(target_os = "macos")]
    unsafe {
        libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0);
        let mut limit = std::mem::zeroed::<libc::rlimit>();
        if libc::getrlimit(libc::RLIMIT_CORE, &mut limit) == 0 {
            CORE_LIMIT.get_or_init(|| limit.rlim_cur);
            limit.rlim_cur = 0;
            libc::setrlimit(libc::RLIMIT_CORE, &limit);
        }
    }
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
