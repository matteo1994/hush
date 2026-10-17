//! `hush run` refuses debugger attach and core dumps for itself, and leaves
//! its child as it would have been. Runs the real binary, with no names in
//! scope, so no vault is needed.

use std::path::PathBuf;
use std::process::Command;

/// Runs `outer` with `$HUSH` set to the binary, in an empty home and
/// directory, so `hush run` there finds no names and needs no vault.
fn sh(name: &str, outer: &str) -> String {
    let dir: PathBuf =
        std::env::temp_dir().join(format!("hush-harden-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let out = Command::new("sh")
        .args(["-c", outer])
        .current_dir(&dir)
        .env("HOME", &dir)
        .env("HUSH", env!("CARGO_BIN_EXE_hush"))
        .env_remove("HUSH_ACTIVE")
        .output()
        .unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(out.status.success(), "{out:?}");
    String::from_utf8(out.stdout).unwrap()
}

/// hush drops its own soft limit to 0; the child must get back the one hush
/// started with. Raised to the hard limit first, so it isn't 0 already.
#[test]
fn child_keeps_the_core_limit_hush_started_with() {
    let seen = sh(
        "core",
        r#"ulimit -c "$(ulimit -H -c)" && ulimit -c && "$HUSH" run -- sh -c 'ulimit -c'"#,
    );
    let lines: Vec<&str> = seen.lines().collect();
    assert_eq!(lines.len(), 2, "{seen}");
    assert_eq!(lines[0], lines[1]);
}

/// On Linux a non-dumpable process's `/proc` files belong to root, so its
/// child can neither read them nor ptrace it.
#[cfg(target_os = "linux")]
#[test]
fn child_cannot_read_hush_memory() {
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("running as root, which may read anything; skipping");
        return;
    }
    let child = "cat /proc/$PPID/environ >/dev/null 2>&1 && echo parent readable; \
                 cat /proc/self/environ >/dev/null && echo self readable";
    let seen = sh("proc", &format!(r#"exec "$HUSH" run -- sh -c '{child}'"#));
    assert_eq!(seen, "self readable\n");
}
