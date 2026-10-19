//! `hush secret` with `--profile`, through the built binary and a vault in a
//! throwaway home.

use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

struct Home(PathBuf);

impl Home {
    fn new(name: &str) -> Home {
        let dir = std::env::temp_dir().join(format!("hush-secret-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let home = Home(dir);
        home.ok(&["init"]);
        home
    }

    /// Detached from any terminal, so a confirmation fails at once instead
    /// of waiting on the terminal `cargo test` runs in.
    fn hush(&self, args: &[&str]) -> Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_hush"));
        // SAFETY: setsid is async-signal-safe.
        unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
        cmd.args(args)
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap())
            .env("HOME", &self.0)
            .env("HUSH_PASSPHRASE", "pw")
            .env("HUSH_SECRET_VALUE", "REAL")
            .stdin(Stdio::null())
            .output()
            .unwrap()
    }

    /// stdout of a command that must succeed.
    fn ok(&self, args: &[&str]) -> String {
        let out = self.hush(args);
        assert!(out.status.success(), "{args:?}: {out:?}");
        String::from_utf8(out.stdout).unwrap()
    }

    /// stderr of a command that must fail.
    fn fails(&self, args: &[&str]) -> String {
        let out = self.hush(args);
        assert!(!out.status.success(), "{args:?}: {out:?}");
        String::from_utf8(out.stderr).unwrap()
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn profiles_hold_their_own_entries_next_to_the_unprofiled_ones() {
    let home = Home::new("profiles");
    home.ok(&[
        "secret",
        "add",
        "OPENAI_API_KEY",
        "--host",
        "api.openai.com",
    ]);
    home.ok(&["secret", "add", "GITHUB_KEY", "--host", "api.github.com"]);
    let out = home.hush(&[
        "secret",
        "add",
        "OPENAI_API_KEY",
        "--host",
        "acme.openai.azure.com",
        "--profile",
        "acme",
    ]);
    assert!(out.status.success(), "{out:?}");
    // Not a replacement of the unprofiled entry, so no confirmation, but
    // it says which one acme's runs will use.
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("instead of the unprofiled one"), "{stderr}");
    home.ok(&[
        "secret",
        "bind",
        "OPENAI_API_KEY",
        "--host",
        "staging.openai.azure.com",
        "--env",
        "staging",
        "--profile",
        "acme",
    ]);

    let all = home.ok(&["secret", "ls"]);
    assert_eq!(
        all,
        "GITHUB_KEY\n  [default] host=api.github.com header=Authorization format=\"Bearer {value}\"\n\
         OPENAI_API_KEY\n  [default] host=api.openai.com header=Authorization format=\"Bearer {value}\"\n\
         OPENAI_API_KEY (profile acme)\n  [default] host=acme.openai.azure.com header=Authorization format=\"Bearer {value}\"\n  \
         [staging] host=staging.openai.azure.com header=Authorization format=\"Bearer {value}\"\n"
    );
    // What a run with acme gets: acme's OPENAI_API_KEY, the shared GITHUB_KEY.
    let acme = home.ok(&["secret", "ls", "--profile", "acme"]);
    let names: Vec<_> = acme.lines().filter(|l| !l.starts_with(' ')).collect();
    assert_eq!(names, ["GITHUB_KEY", "OPENAI_API_KEY (profile acme)"]);

    // Removing acme's entry leaves the unprofiled one, and the empty profile goes.
    home.ok(&["secret", "rm", "OPENAI_API_KEY", "--profile", "acme"]);
    let all = home.ok(&["secret", "ls"]);
    assert!(all.contains("host=api.openai.com"), "{all}");
    assert!(!all.contains("profile acme"), "{all}");
    assert!(
        home.fails(&["secret", "ls", "--profile", "acme"])
            .contains("no such profile: acme")
    );
}

#[test]
fn profile_commands_touch_only_their_profile() {
    let home = Home::new("scoped");
    home.ok(&["secret", "add", "KEY", "--host", "api.example.com"]);

    // The unprofiled KEY isn't in acme, so neither bind nor rm find it there.
    let bind = home.fails(&[
        "secret",
        "bind",
        "KEY",
        "--host",
        "x.example.com",
        "--env",
        "e",
        "--profile",
        "acme",
    ]);
    assert!(
        bind.contains("no such secret: KEY in profile acme"),
        "{bind}"
    );
    let rm = home.fails(&["secret", "rm", "KEY", "--profile", "acme"]);
    assert!(rm.contains("no such secret: KEY in profile acme"), "{rm}");
    assert!(home.ok(&["secret", "ls"]).contains("KEY\n"));

    // And an entry only in acme isn't removed without --profile.
    home.ok(&[
        "secret",
        "add",
        "ONLY_KEY",
        "--host",
        "api.example.com",
        "--profile",
        "acme",
    ]);
    let rm = home.fails(&["secret", "rm", "ONLY_KEY"]);
    assert!(rm.contains("no such secret: ONLY_KEY\n"), "{rm}");
}

#[test]
fn bad_profile_names_are_refused() {
    let home = Home::new("names");
    for bad in ["", "a b", "a/b", "ü", ".", "..", ".acme", "-acme", "_acme"] {
        let err = home.fails(&["secret", "ls", &format!("--profile={bad}")]);
        assert!(
            err.contains("start with a letter or digit"),
            "{bad:?}: {err}"
        );
    }
    for good in ["acme", "acme.prod", "2026-q4", "a_b"] {
        let err = home.fails(&["secret", "ls", "--profile", good]);
        assert!(err.contains("no such profile"), "{good:?}: {err}");
    }
}

#[test]
fn replacing_an_entry_in_a_profile_asks_and_rm_keeps_a_profile_that_has_more() {
    let home = Home::new("replace");
    let add = |host: &str, extra: &[&str]| {
        let mut args = vec!["secret", "add", "KEY", "--host", host, "--profile", "acme"];
        args.extend_from_slice(extra);
        home.hush(&args)
    };
    assert!(add("old.example.com", &[]).status.success());
    home.ok(&[
        "secret",
        "add",
        "OTHER_KEY",
        "--host",
        "api.example.com",
        "--profile",
        "acme",
    ]);

    // There's no terminal to ask on, so without --force it refuses.
    let out = add("new.example.com", &[]);
    assert!(!out.status.success(), "{out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("KEY already exists, bound to:"), "{stderr}");
    assert!(stderr.contains("pass --force"), "{stderr}");
    assert!(home.ok(&["secret", "ls"]).contains("host=old.example.com"));

    assert!(add("new.example.com", &["--force"]).status.success());
    let all = home.ok(&["secret", "ls"]);
    assert!(
        all.contains("host=new.example.com") && !all.contains("host=old.example.com"),
        "{all}"
    );

    home.ok(&["secret", "rm", "KEY", "--profile", "acme"]);
    let acme = home.ok(&["secret", "ls", "--profile", "acme"]);
    assert_eq!(
        acme.lines().next(),
        Some("OTHER_KEY (profile acme)"),
        "{acme}"
    );
}
