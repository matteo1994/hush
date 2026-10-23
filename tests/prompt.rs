//! Inside `hush run`, every passphrase prompt comes with a warning, since the
//! command may have been started by an agent that can read the terminal.

use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Output};

/// `hush args...` with `home` as its home, detached from any terminal so a
/// prompt fails at once instead of waiting.
fn hush(home: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_hush"));
    cmd.args(args)
        .env("HOME", home)
        .env_remove("HUSH_ACTIVE")
        .env_remove("HUSH_PASSPHRASE")
        .envs(env.iter().copied());
    // SAFETY: setsid is async-signal-safe.
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    cmd.output().unwrap()
}

#[test]
fn every_prompt_inside_hush_run_warns() {
    let home = std::env::temp_dir().join(format!("hush-prompt-{}", std::process::id()));
    std::fs::create_dir_all(&home).unwrap();
    let init = hush(&home, &["init"], &[("HUSH_PASSPHRASE", "pw")]);
    assert!(init.status.success(), "{init:?}");

    for args in [
        &["secret", "ls"][..],
        &["secret", "rm", "X"],
        &["secret", "set", "X"],
        &["passwd"],
    ] {
        let inside = hush(&home, args, &[("HUSH_ACTIVE", "1")]);
        let stderr = String::from_utf8_lossy(&inside.stderr);
        assert!(stderr.contains("WARNING"), "{args:?}: {stderr}");
        assert!(stderr.contains("no terminal"), "{args:?}: {stderr}");
        assert_eq!(stderr.matches("WARNING").count(), 1, "{args:?}: {stderr}");

        let outside = hush(&home, args, &[]);
        let stderr = String::from_utf8_lossy(&outside.stderr);
        assert!(!stderr.contains("WARNING"), "{args:?}: {stderr}");
    }
    std::fs::remove_dir_all(&home).unwrap();
}
