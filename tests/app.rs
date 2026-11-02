//! `hush app add` end to end: the launcher it writes, run the way
//! LaunchServices would, with a stand-in for `osascript` that records alerts.
#![cfg(target_os = "macos")]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const REAL: &str = "sk-live-0123456789abcdef";

struct Home(PathBuf);

impl Home {
    fn new(name: &str) -> Home {
        let dir = std::env::temp_dir()
            .join(format!("hush-app-{name}-{}", std::process::id()))
            .canonicalize_or_self();
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("bin")).unwrap();
        let home = Home(dir);
        write_executable(
            &home.0.join("bin/osascript"),
            "#!/bin/sh\nfor last; do :; done\nprintf '%s\\n' \"$last\" >>\"$HOME/alerts\"\n",
        );
        home
    }

    fn with_key(name: &str) -> Home {
        let home = Home::new(name);
        assert_ok(home.hush(&["init"]).output().unwrap());
        let mut add = home.hush(&["secret", "add", "DEMO_KEY", "--host", "api.example.com"]);
        add.env("HUSH_SECRET_VALUE", REAL);
        assert_ok(add.output().unwrap());
        home
    }

    fn hush(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_hush"));
        cmd.args(args)
            .current_dir(&self.0)
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap())
            .env("HOME", &self.0)
            .env("HUSH_PASSPHRASE", "pw")
            .stdin(Stdio::null());
        cmd
    }

    /// A bundle whose binary is `body`, as a shell script.
    fn fake_app(&self, name: &str, body: &str) -> PathBuf {
        let bundle = self.0.join(format!("{name}.app"));
        fs::create_dir_all(bundle.join("Contents/MacOS")).unwrap();
        fs::write(
            bundle.join("Contents/Info.plist"),
            format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>fake</string>
<key>CFBundleIdentifier</key><string>test.{name}</string>
</dict></plist>
"#
            ),
        )
        .unwrap();
        write_executable(&bundle.join("Contents/MacOS/fake"), body);
        bundle
    }

    fn launcher(&self, name: &str) -> PathBuf {
        self.0.join(format!("Applications/{name} (hush).app"))
    }

    /// The launcher's script, in an environment like launchd's: no terminal,
    /// `/` as the working directory, and only a basic `PATH`.
    fn launch(&self, name: &str) -> Output {
        let script = self.launcher(name).join("Contents/MacOS/hush-launcher");
        Command::new(script)
            .current_dir("/")
            .env_clear()
            .env("HOME", &self.0)
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", self.0.join("bin").display()),
            )
            .env("HUSH_PASSPHRASE", "pw")
            .stdin(Stdio::null())
            .output()
            .unwrap()
    }

    fn alerts(&self) -> String {
        fs::read_to_string(self.0.join("alerts")).unwrap_or_default()
    }

    fn log(&self, name: &str) -> String {
        fs::read_to_string(self.0.join(format!("Library/Logs/hush/{name}.log"))).unwrap()
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

trait CanonicalizeOrSelf {
    fn canonicalize_or_self(self) -> PathBuf;
}

impl CanonicalizeOrSelf for PathBuf {
    /// The temp dir is behind a symlink on macOS; the parent exists.
    fn canonicalize_or_self(self) -> PathBuf {
        let parent = self.parent().unwrap().canonicalize().unwrap();
        parent.join(self.file_name().unwrap())
    }
}

fn write_executable(path: &Path, body: &str) {
    fs::write(path, body).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

fn assert_ok(out: Output) {
    assert!(out.status.success(), "{out:?}");
}

#[test]
fn a_launcher_starts_the_app_under_hush_run_and_holds_no_secret() {
    let home = Home::with_key("start");
    let report = home.0.join("report");
    let app = home.fake_app(
        "Fake",
        &format!(
            "#!/bin/sh\n{{ echo \"key=$DEMO_KEY\"; echo \"active=$HUSH_ACTIVE\"; echo \"proxy=$HTTPS_PROXY\"; echo \"pass=$HUSH_PASSPHRASE\"; for a; do echo \"arg=$a\"; done; }} >'{}'\n",
            report.display()
        ),
    );
    let app = app.to_str().unwrap();
    assert_ok(
        home.hush(&[
            "app",
            "add",
            app,
            "--secret",
            "DEMO_KEY",
            "--",
            "--flag",
            "two words",
        ])
        .output()
        .unwrap(),
    );

    let out = home.launch("Fake");
    assert!(out.status.success(), "{out:?}\n{}", home.log("Fake"));
    let report = fs::read_to_string(report).unwrap();
    assert!(report.contains("key=hush_ph_"), "{report}");
    assert!(report.contains("active=1"), "{report}");
    assert!(report.contains("proxy=http://127.0.0.1:"), "{report}");
    assert!(report.contains("pass=\n"), "{report}");
    assert!(report.contains("arg=--flag\narg=two words\n"), "{report}");
    assert!(!report.contains(REAL), "{report}");
    assert_eq!(home.alerts(), "");

    for file in ["Contents/Info.plist", "Contents/MacOS/hush-launcher"] {
        let text = fs::read_to_string(home.launcher("Fake").join(file)).unwrap();
        assert!(!text.contains(REAL), "{text}");
        assert!(!text.contains("HUSH_PASSPHRASE"), "{text}");
    }
    assert_ok(
        Command::new("/usr/bin/plutil")
            .arg("-lint")
            .arg(home.launcher("Fake").join("Contents/Info.plist"))
            .output()
            .unwrap(),
    );
}

#[test]
fn a_failed_run_shows_hushs_own_lines_in_an_alert() {
    let home = Home::with_key("alert");
    let app = home.fake_app("Fake", "#!/bin/sh\n");
    assert_ok(
        home.hush(&["app", "add", app.to_str().unwrap(), "--secret", "DEMO_KEY"])
            .output()
            .unwrap(),
    );
    fs::remove_file(app.join("Contents/MacOS/fake")).unwrap();

    let out = home.launch("Fake");
    assert!(!out.status.success(), "{out:?}");
    assert!(home.alerts().contains("hush: "), "{}", home.alerts());
}

#[test]
fn an_app_failing_on_its_own_shows_no_alert_and_keeps_its_exit_code() {
    let home = Home::with_key("exit");
    let app = home.fake_app("Fake", "#!/bin/sh\necho app noise >&2\nexit 3\n");
    assert_ok(
        home.hush(&["app", "add", app.to_str().unwrap(), "--secret", "DEMO_KEY"])
            .output()
            .unwrap(),
    );

    let out = home.launch("Fake");
    assert_eq!(out.status.code(), Some(3), "{out:?}");
    assert_eq!(home.alerts(), "");
    assert!(home.log("Fake").contains("app noise"));
}

#[test]
fn a_moved_hush_is_reported() {
    let home = Home::with_key("moved");
    let copy = home.0.join("bin/hush-copy");
    fs::copy(env!("CARGO_BIN_EXE_hush"), &copy).unwrap();
    let app = home.fake_app("Fake", "#!/bin/sh\n");
    let mut add = Command::new(&copy);
    add.args(["app", "add", app.to_str().unwrap(), "--secret", "DEMO_KEY"])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &home.0);
    assert_ok(add.output().unwrap());
    fs::remove_file(&copy).unwrap();

    let out = home.launch("Fake");
    assert_eq!(out.status.code(), Some(127), "{out:?}");
    assert!(home.alerts().contains("hush-copy"), "{}", home.alerts());
}

#[test]
fn only_force_replaces_a_launcher_and_nothing_replaces_another_app() {
    let home = Home::new("force");
    let app = home.fake_app("Fake", "#!/bin/sh\n");
    let app = app.to_str().unwrap();
    assert_ok(home.hush(&["app", "add", app]).output().unwrap());

    let again = home.hush(&["app", "add", app]).output().unwrap();
    assert!(!again.status.success());
    assert!(
        String::from_utf8_lossy(&again.stderr).contains("--force"),
        "{again:?}"
    );
    assert_ok(home.hush(&["app", "add", app, "--force"]).output().unwrap());

    // Someone else's bundle at that path stays, whatever the flags.
    let dest = home.launcher("Fake");
    fs::remove_dir_all(&dest).unwrap();
    fs::create_dir_all(dest.join("Contents")).unwrap();
    fs::write(dest.join("Contents/mine"), "keep").unwrap();
    let refused = home.hush(&["app", "add", app, "--force"]).output().unwrap();
    assert!(!refused.status.success());
    assert_eq!(
        fs::read_to_string(dest.join("Contents/mine")).unwrap(),
        "keep"
    );

    // A launcher isn't an app to make a launcher of.
    fs::remove_dir_all(&dest).unwrap();
    assert_ok(home.hush(&["app", "add", app]).output().unwrap());
    let nested = home
        .hush(&["app", "add", dest.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!nested.status.success());
    assert!(
        String::from_utf8_lossy(&nested.stderr).contains("launcher"),
        "{nested:?}"
    );
}
