//! `hush secret` with `--profile`, through the built binary and a vault in a
//! throwaway home.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
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
        self.hush_in(&self.0, args)
    }

    fn command_in(&self, dir: &Path, args: &[&str]) -> Command {
        self.command_of(Path::new(env!("CARGO_BIN_EXE_hush")), dir, args)
    }

    fn command_of(&self, program: &Path, dir: &Path, args: &[&str]) -> Command {
        let mut cmd = Command::new(program);
        // SAFETY: setsid is async-signal-safe.
        unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
        cmd.args(args)
            .current_dir(dir)
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap())
            .env("HOME", &self.0)
            .env("HUSH_PASSPHRASE", "pw")
            .env("HUSH_SECRET_VALUE", "REAL")
            .stdin(Stdio::null());
        cmd
    }

    fn hush_in(&self, dir: &Path, args: &[&str]) -> Output {
        self.command_in(dir, args).output().unwrap()
    }

    fn command(&self, args: &[&str]) -> Command {
        self.command_in(&self.0, args)
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
        "GITHUB_KEY\n  rotated just now\n  [default] host=api.github.com header=Authorization format=\"Bearer {value}\"\n\
         OPENAI_API_KEY\n  rotated just now\n  [default] host=api.openai.com header=Authorization format=\"Bearer {value}\"\n\
         OPENAI_API_KEY (profile acme)\n  rotated just now\n  [default] host=acme.openai.azure.com header=Authorization format=\"Bearer {value}\"\n  \
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

#[test]
fn profile_use_maps_the_project_and_ls_lists_the_mappings() {
    let home = Home::new("use");
    let root = home.0.canonicalize().unwrap();
    let acme = root.join("acme");
    let src = acme.join("src");
    let old = root.join("old");
    for dir in [&acme.join(".git"), &src, &old] {
        std::fs::create_dir_all(dir).unwrap();
    }
    let in_src = |args: &[&str]| home.hush_in(&src, args);
    let stderr = |out: &Output| String::from_utf8_lossy(&out.stderr).into_owned();

    // Only a profile that holds something can be mapped.
    let out = in_src(&["profile", "use", "acme"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("no such profile: acme"), "{out:?}");
    home.ok(&[
        "secret",
        "add",
        "KEY",
        "--host",
        "api.example.com",
        "--profile",
        "acme",
    ]);

    std::fs::write(root.join("file"), "").unwrap();
    for which in ["acme", "--none"] {
        let out = home.hush(&["profile", "use", which, "--dir", "file"]);
        assert!(stderr(&out).contains("not a directory"), "{which}: {out:?}");
    }

    // Where acme's project used to be, before it moved.
    home.ok(&["profile", "use", "acme", "--dir", "old"]);
    std::fs::remove_dir(&old).unwrap();
    assert_eq!(
        home.ok(&["profile", "ls"]),
        format!("acme: 1 entry\n  {} (no longer exists)\n", old.display())
    );

    // From a subdirectory, the git root is what's mapped. The old place is
    // pointed out, not removed: an unmounted volume looks the same.
    let out = in_src(&["profile", "use", "acme"]);
    assert!(out.status.success(), "{out:?}");
    let err = stderr(&out);
    assert!(
        err.contains(&format!("mapping {} to profile acme", acme.display())),
        "{err}"
    );
    assert!(
        err.contains(&format!(
            "{}, also mapped to acme, no longer exists",
            old.display()
        )),
        "{err}"
    );
    let again = in_src(&["profile", "use", "acme"]);
    assert!(stderr(&again).contains("already mapped"), "{again:?}");

    // A gone directory's mapping, removed by a relative path through a
    // symlink: still the spelling it was stored under.
    let link = root.join("link");
    std::os::unix::fs::symlink(&acme, &link).unwrap();
    let out = home.hush_in(&link, &["profile", "use", "--none", "--dir", "../x/../old"]);
    assert!(out.status.success(), "{out:?}");
    assert_eq!(
        home.ok(&["profile", "ls"]),
        format!("acme: 1 entry\n  {}\n", acme.display())
    );

    // --none removes it; a mapping above the directory isn't touched.
    let out = home.hush_in(&src, &["profile", "use", "--none", "--dir", "."]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("runs there use profile acme"),
        "{out:?}"
    );
    assert!(in_src(&["profile", "use", "--none"]).status.success());
    assert_eq!(home.ok(&["profile", "ls"]), "acme: 1 entry\n");
    let out = in_src(&["profile", "use", "--none"]);
    assert!(stderr(&out).contains("no profile is mapped to"), "{out:?}");

    // Removing a profile's last entry keeps its mappings, and says so.
    assert!(in_src(&["profile", "use", "acme"]).status.success());
    let out = home.hush(&["secret", "rm", "KEY", "--profile", "acme"]);
    assert!(out.status.success(), "{out:?}");
    assert!(stderr(&out).contains("is still mapped to it"), "{out:?}");
    assert_eq!(
        home.ok(&["profile", "ls"]),
        format!(
            "acme: not in the vault, runs use the unprofiled entries\n  {}\n",
            acme.display()
        )
    );

    // Mapping it to another profile says which it replaces.
    home.ok(&[
        "secret",
        "add",
        "KEY",
        "--host",
        "api.example.com",
        "--profile",
        "beta",
    ]);
    let out = in_src(&["profile", "use", "beta"]);
    assert!(
        stderr(&out).contains("it was mapped to profile acme"),
        "{out:?}"
    );
    assert!(
        home.ok(&["profile", "ls"])
            .ends_with(&format!("beta: 1 entry\n  {}\n", acme.display())),
    );

    // A name, or --none, but not both.
    assert!(!in_src(&["profile", "use"]).status.success());
    assert!(
        !in_src(&["profile", "use", "acme", "--none"])
            .status
            .success()
    );
}

#[test]
fn set_keeps_bindings_and_refuses_an_unknown_name() {
    let home = Home::new("set");
    let err = home.fails(&["secret", "set", "MISSING"]);
    assert!(
        err.contains("no such secret: MISSING")
            && err.contains("hush secret add MISSING --host HOST"),
        "{err}"
    );
    assert!(!err.contains("REAL"), "{err}");

    home.ok(&["secret", "add", "KEY", "--host", "api.example.com"]);
    home.ok(&[
        "secret",
        "bind",
        "KEY",
        "--host",
        "staging.example.com",
        "--env",
        "staging",
    ]);
    let out = home.hush(&["secret", "set", "KEY"]);
    assert!(out.status.success(), "{out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stderr.contains("keeping its bindings"), "{stderr}");
    assert!(
        stderr.contains("host=api.example.com") && stderr.contains("host=staging.example.com"),
        "{stderr}"
    );
    assert!(
        !stderr.contains("REAL") && !stdout.contains("REAL"),
        "{out:?}"
    );

    let ls = home.ok(&["secret", "ls"]);
    assert!(
        ls.contains("host=api.example.com") && ls.contains("host=staging.example.com"),
        "{ls}"
    );
    assert!(!ls.contains("REAL"), "{ls}");

    let err = home.fails(&["secret", "set", "KEY", "--profile", "acme"]);
    assert!(
        err.contains("no such secret: KEY in profile acme") && err.contains("--profile acme"),
        "{err}"
    );
    // The unprofiled entry is untouched by the failed profile set.
    assert!(home.ok(&["secret", "ls"]).contains("host=api.example.com"));
}

/// Typed at a terminal, the value would echo, so `--stdin` there is refused
/// before anything is read or the vault is touched.
#[test]
fn set_stdin_refuses_a_terminal() {
    let home = Home::new("set-stdin-tty");
    home.ok(&["secret", "add", "KEY", "--host", "api.example.com"]);
    let vault = home.0.join(".config/hush/vault.age");
    let before = std::fs::read(&vault).unwrap();
    let (mut leader, mut follower) = (0, 0);
    // SAFETY: both out-pointers are valid; the name, termios and winsize may
    // be null (null_mut, since macOS takes the last two as `*mut`).
    let rc = unsafe {
        libc::openpty(
            &mut leader,
            &mut follower,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rc, 0, "openpty");
    // SAFETY: openpty returned these descriptors, and nothing else owns them.
    let (leader, follower) = unsafe {
        use std::os::fd::FromRawFd;
        (
            std::fs::File::from_raw_fd(leader),
            std::fs::File::from_raw_fd(follower),
        )
    };
    // A line and then end-of-file, so that if the check were gone the read
    // would finish and set the value instead of waiting forever.
    (&leader).write_all(b"typed-value\n\x04").unwrap();
    let out = home
        .command(&["secret", "set", "KEY", "--stdin"])
        .stdin(follower)
        .output()
        .unwrap();
    drop(leader);
    assert!(!out.status.success(), "{out:?}");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("stdin is a terminal"), "{err}");
    assert_eq!(std::fs::read(&vault).unwrap(), before);
}

#[test]
fn set_stdin_does_not_echo_the_value() {
    let home = Home::new("set-stdin");
    home.ok(&["secret", "add", "KEY", "--host", "api.example.com"]);
    let value = "stdin-secret-value\n";
    let mut cmd = home.command(&["secret", "set", "KEY", "--stdin"]);
    cmd.env("HUSH_SECRET_VALUE", "NOT-THE-STDIN-VALUE")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(value.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "{out:?}");
    let text = String::from_utf8(out.stderr).unwrap() + &String::from_utf8(out.stdout).unwrap();
    assert!(!text.contains("stdin-secret-value"), "{text}");
    assert!(!text.contains("NOT-THE-STDIN-VALUE"), "{text}");
}

/// An empty pipe, as from a password manager command that failed, must not
/// wipe the key.
#[test]
fn set_refuses_an_empty_value() {
    let home = Home::new("set-empty");
    home.ok(&["secret", "add", "KEY", "--host", "api.example.com"]);
    let vault = home.0.join(".config/hush/vault.age");
    let before = std::fs::read(&vault).unwrap();
    // `command` gives the child a null stdin, which reads as empty.
    let err = home.fails(&["secret", "set", "KEY", "--stdin"]);
    assert!(err.contains("empty; left it unchanged"), "{err}");
    let out = home
        .command(&["secret", "set", "KEY"])
        .env("HUSH_SECRET_VALUE", "")
        .output()
        .unwrap();
    assert!(!out.status.success(), "{out:?}");
    assert_eq!(std::fs::read(&vault).unwrap(), before);
}

#[test]
fn passwd_reencrypts_and_leaves_the_old_vault_on_failure() {
    let home = Home::new("passwd");
    home.ok(&["secret", "add", "KEY", "--host", "api.example.com"]);
    let path = home.0.join(".config/hush/vault.age");
    let before = std::fs::read(&path).unwrap();

    let fail = |pass: &str, new: &str| {
        let mut cmd = home.command(&["passwd"]);
        cmd.env("HUSH_PASSPHRASE", pass)
            .env("HUSH_NEW_PASSPHRASE", new);
        let out = cmd.output().unwrap();
        assert!(!out.status.success(), "{pass:?} {new:?}: {out:?}");
        String::from_utf8(out.stderr).unwrap()
    };
    let err = fail("nope", "pw2");
    assert!(err.contains("wrong passphrase"), "{err}");
    assert!(!err.contains("nope") && !err.contains("pw2"), "{err}");
    assert_eq!(
        std::fs::read(&path).unwrap(),
        before,
        "a rejected passphrase rewrote the vault"
    );

    let err = fail("pw", "");
    assert!(err.contains("must not be empty"), "{err}");
    assert_eq!(std::fs::read(&path).unwrap(), before);

    let mut cmd = home.command(&["passwd"]);
    cmd.env("HUSH_PASSPHRASE", "pw")
        .env("HUSH_NEW_PASSPHRASE", "a-new-passphrase");
    let out = cmd.output().unwrap();
    assert!(out.status.success(), "{out:?}");
    let text = String::from_utf8(out.stderr).unwrap() + &String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("vault passphrase changed"), "{text}");
    assert!(!text.contains("a-new-passphrase"), "{text}");

    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    assert!(!path.with_extension("age.tmp").exists());
    assert_ne!(std::fs::read(&path).unwrap(), before);

    let mut ls = home.command(&["secret", "ls"]);
    ls.env("HUSH_PASSPHRASE", "pw");
    let out = ls.output().unwrap();
    assert!(
        !out.status.success(),
        "old passphrase still opens the vault: {out:?}"
    );
    assert!(
        !String::from_utf8_lossy(&out.stderr).contains("a-new-passphrase"),
        "{out:?}"
    );

    let mut ls = home.command(&["secret", "ls"]);
    ls.env("HUSH_PASSPHRASE", "a-new-passphrase");
    let out = ls.output().unwrap();
    assert!(out.status.success(), "{out:?}");
    let listed = String::from_utf8(out.stdout).unwrap();
    assert!(
        listed.contains("KEY") && listed.contains("host=api.example.com"),
        "{listed}"
    );
    assert!(!listed.contains("REAL"), "{listed}");
}

#[test]
fn ls_shows_age_and_a_max_age_can_be_cleared() {
    let home = Home::new("age");
    let err = home.fails(&[
        "secret",
        "add",
        "KEY",
        "--host",
        "api.example.com",
        "--max-age",
        "90",
    ]);
    assert!(err.contains("duration"), "{err}");
    assert!(!err.contains("REAL"), "{err}");
    assert!(!home.ok(&["secret", "ls"]).contains("KEY"), "{err}");

    home.ok(&[
        "secret",
        "add",
        "KEY",
        "--host",
        "api.example.com",
        "--max-age",
        "90d",
    ]);
    let ls = home.ok(&["secret", "ls"]);
    assert!(ls.contains("rotated just now, max age 90d"), "{ls}");
    assert!(!ls.contains("REAL"), "{ls}");

    home.ok(&["secret", "set", "KEY", "--max-age", "none"]);
    let ls = home.ok(&["secret", "ls"]);
    assert!(ls.contains("rotated just now\n"), "{ls}");
    assert!(!ls.contains("max age"), "{ls}");

    // Setting the value without --max-age leaves the limit that was stored.
    home.ok(&["secret", "set", "KEY", "--max-age", "12h"]);
    home.ok(&["secret", "set", "KEY"]);
    let ls = home.ok(&["secret", "ls"]);
    assert!(ls.contains("rotated just now, max age 12h"), "{ls}");
}

#[test]
fn unbind_removes_one_binding_and_keeps_the_secret() {
    let home = Home::new("unbind");
    home.ok(&["secret", "add", "KEY", "--host", "api.example.com"]);
    home.ok(&[
        "secret",
        "bind",
        "KEY",
        "--host",
        "api.example.com",
        "--env",
        "staging",
    ]);
    home.ok(&[
        "secret",
        "bind",
        "KEY",
        "--host",
        "other.example.com",
        "--env",
        "qa",
    ]);

    let err = home.fails(&["secret", "bind", "KEY", "--host", "evil.example.com"]);
    assert!(err.contains("hush secret unbind"), "{err}");
    assert!(!err.contains("REAL"), "{err}");

    let err = home.fails(&["secret", "unbind", "KEY", "--host", "api.example.com"]);
    assert!(err.contains("pass --env"), "{err}");
    assert!(home.ok(&["secret", "ls"]).contains("[staging]"), "{err}");

    home.ok(&[
        "secret",
        "unbind",
        "KEY",
        "--host",
        "API.example.com",
        "--env",
        "staging",
    ]);
    let ls = home.ok(&["secret", "ls"]);
    assert!(ls.contains("[default] host=api.example.com"), "{ls}");
    assert!(!ls.contains("staging"), "{ls}");
    assert!(ls.contains("other.example.com"), "{ls}");
    assert!(!ls.contains("REAL"), "{ls}");

    home.ok(&["secret", "unbind", "KEY", "--host", "other.example.com"]);
    let out = home.hush(&["secret", "unbind", "KEY", "--host", "api.example.com"]);
    assert!(out.status.success(), "{out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("no bindings left"), "{stderr}");
    assert!(!stderr.contains("REAL"), "{stderr}");
    let ls = home.ok(&["secret", "ls"]);
    assert!(ls.contains("KEY\n"), "{ls}");
    assert!(!ls.contains("host="), "{ls}");

    let err = home.fails(&[
        "secret",
        "unbind",
        "KEY",
        "--host",
        "api.example.com",
        "--profile",
        "acme",
    ]);
    assert!(err.contains("no such secret: KEY in profile acme"), "{err}");
}

#[test]
fn cp_copies_the_whole_entry_and_mv_drops_an_emptied_profile() {
    let home = Home::new("cp-mv");
    home.ok(&["secret", "add", "KEY", "--host", "api.example.com"]);
    home.ok(&[
        "secret",
        "bind",
        "KEY",
        "--host",
        "staging.example.com",
        "--env",
        "staging",
    ]);

    let out = home.hush(&["secret", "cp", "KEY", "--to", "acme"]);
    assert!(out.status.success(), "{out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("set it in both places"), "{stderr}");
    assert!(stderr.contains("instead of the unprofiled one"), "{stderr}");
    assert!(!stderr.contains("REAL"), "{stderr}");
    let acme = home.ok(&["secret", "ls", "--profile", "acme"]);
    assert!(
        acme.contains("KEY (profile acme)")
            && acme.contains("host=api.example.com")
            && acme.contains("[staging] host=staging.example.com"),
        "{acme}"
    );

    let err = home.fails(&["secret", "cp", "KEY", "--to", "acme"]);
    assert!(
        err.contains("already exists in profile acme") && err.contains("--force"),
        "{err}"
    );
    // --force lists what it replaces, and says when that drops a live value.
    let out = home.hush(&["secret", "cp", "KEY", "--to", "acme", "--force"]);
    assert!(out.status.success(), "{out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("which holds the same value") && !stderr.contains("stops redacting"),
        "{stderr}"
    );
    let out = home
        .command(&["secret", "set", "KEY", "--profile", "acme"])
        .env("HUSH_SECRET_VALUE", "ACME")
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    let out = home.hush(&["secret", "cp", "KEY", "--to", "acme", "--force"]);
    assert!(out.status.success(), "{out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("which holds a different value")
            && stderr.contains("[staging] host=staging.example.com")
            && stderr.contains("stops redacting"),
        "{stderr}"
    );
    assert!(
        !stderr.contains("REAL") && !stderr.contains("ACME"),
        "{stderr}"
    );
    let err = home.fails(&["secret", "cp", "KEY", "--from", "acme", "--to", "acme"]);
    assert!(err.contains("onto itself"), "{err}");
    let err = home.fails(&["secret", "cp", "MISSING", "--to", "acme"]);
    assert!(
        err.contains("no such secret: MISSING in the unprofiled entries"),
        "{err}"
    );

    // Moving acme's only entry to another profile removes acme.
    home.ok(&["secret", "mv", "KEY", "--from", "acme", "--to", "beta"]);
    assert!(
        home.fails(&["secret", "ls", "--profile", "acme"])
            .contains("no such profile: acme")
    );
    let ls = home.ok(&["secret", "ls"]);
    assert!(
        ls.contains("KEY (profile beta)") && ls.contains("KEY\n"),
        "{ls}"
    );
    assert!(!ls.contains("REAL"), "{ls}");

    // Moving to the unprofiled entries needs --force, since KEY is there.
    let err = home.fails(&["secret", "mv", "KEY", "--from", "beta"]);
    assert!(
        err.contains("already exists in the unprofiled entries"),
        "{err}"
    );
    home.ok(&["secret", "mv", "KEY", "--from", "beta", "--force"]);
    let ls = home.ok(&["secret", "ls"]);
    assert!(!ls.contains("profile beta") && ls.contains("KEY\n"), "{ls}");
}

#[test]
fn set_names_the_other_entries_that_still_hold_the_old_value() {
    let home = Home::new("set-others");
    home.ok(&["secret", "add", "KEY", "--host", "api.example.com"]);
    home.ok(&["secret", "cp", "KEY", "--to", "acme"]);
    home.ok(&["secret", "add", "ALIAS_KEY", "--host", "api.example.com"]);
    let out = home
        .command(&["secret", "add", "OTHER", "--host", "api.example.com"])
        .env("HUSH_SECRET_VALUE", "DIFFERENT")
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");

    // The same value again changes nothing, so nothing is named.
    let out = home.hush(&["secret", "set", "KEY"]);
    assert!(out.status.success(), "{out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stderr.contains("set it there too"), "{stderr}");

    let out = home
        .command(&["secret", "set", "KEY"])
        .env("HUSH_SECRET_VALUE", "NEW")
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("KEY in profile acme held the same value")
            && stderr.contains("ALIAS_KEY in the unprofiled entries held the same value"),
        "{stderr}"
    );
    assert!(!stderr.contains("OTHER"), "{stderr}");
    assert!(
        !stderr.contains("REAL") && !stderr.contains("NEW"),
        "{stderr}"
    );
}

/// An unsigned hush warns at its first prompt that an injected library could
/// read the passphrase; the same binary signed with the hardened runtime
/// doesn't. A value from `HUSH_PASSPHRASE` is no prompt, so no warning.
#[cfg(target_os = "macos")]
#[test]
fn a_prompt_warns_when_hush_lacks_the_hardened_runtime() {
    let home = Home::new("hardened");
    let warning = "isn't signed with the hardened runtime";

    let out = home.hush(&["secret", "ls"]);
    assert!(out.status.success(), "{out:?}");
    assert!(
        !String::from_utf8_lossy(&out.stderr).contains(warning),
        "{out:?}"
    );

    let prompt = |program: &Path| {
        let out = home
            .command_of(program, &home.0, &["secret", "ls"])
            .env_remove("HUSH_PASSPHRASE")
            .output()
            .unwrap();
        // Detached from the terminal, the prompt itself fails.
        assert!(!out.status.success(), "{out:?}");
        String::from_utf8(out.stderr).unwrap()
    };
    let unsigned = prompt(Path::new(env!("CARGO_BIN_EXE_hush")));
    assert!(
        unsigned.contains(warning) && unsigned.contains("codesign"),
        "{unsigned}"
    );
    assert!(unsigned.contains("no terminal"), "{unsigned}");
    let exe = std::fs::canonicalize(env!("CARGO_BIN_EXE_hush")).unwrap();
    assert!(
        unsigned.contains(&format!("\"{}\"", exe.display())),
        "{unsigned}"
    );

    // A library actually loaded, which leaves the variable set: the alarm.
    let src = home.0.join("inject.c");
    std::fs::write(&src, "void hush_test_injected(void) {}\n").unwrap();
    let lib = home.0.join("inject.dylib");
    let status = Command::new("/usr/bin/clang")
        .args(["-dynamiclib", "-o"])
        .arg(&lib)
        .arg(&src)
        .status()
        .unwrap();
    assert!(status.success());
    let out = home
        .command(&["secret", "ls"])
        .env_remove("HUSH_PASSPHRASE")
        .env("DYLD_INSERT_LIBRARIES", &lib)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("DYLD_INSERT_LIBRARIES is set")
            && stderr.contains("don't enter the passphrase"),
        "{stderr}"
    );

    let signed = home.0.join("hush-hardened");
    std::fs::copy(env!("CARGO_BIN_EXE_hush"), &signed).unwrap();
    let status = Command::new("codesign")
        .args(["-f", "-s", "-", "-o", "runtime"])
        .arg(&signed)
        .status()
        .unwrap();
    assert!(status.success());
    let hardened = prompt(&signed);
    assert!(!hardened.contains(warning), "{hardened}");
    assert!(hardened.contains("no terminal"), "{hardened}");
}
