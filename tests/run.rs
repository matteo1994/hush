//! `hush run` end to end: the real binary, a vault in a throwaway home, a
//! child shell that uses curl through the proxy, and upstream servers on this
//! machine that record what reaches them.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

const REAL: &str = "sk-live-0123456789abcdef";

/// A home directory with its own vault, removed when dropped.
struct Home(PathBuf);

impl Home {
    fn new(name: &str) -> Home {
        let dir = std::env::temp_dir().join(format!("hush-run-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Home(dir)
    }

    /// A vault holding `DEMO_KEY`, bound to `127.0.0.1:port`.
    fn with_key(name: &str, port: u16) -> Home {
        let home = Home::new(name);
        home.ok(home.hush(&["init"]));
        let host = format!("127.0.0.1:{port}");
        let mut add = home.hush(&["secret", "add", "DEMO_KEY", "--host", &host]);
        add.env("HUSH_SECRET_VALUE", REAL);
        home.ok(add);
        home
    }

    /// hush with nothing from this environment but `PATH`, so a developer's
    /// proxy or CA settings can't leak in. The passphrase is set, as hush's
    /// own input that the child must not see.
    fn hush(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_hush"));
        cmd.args(args)
            .current_dir(&self.0)
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap())
            .env("HOME", &self.0)
            .env("HUSH", env!("CARGO_BIN_EXE_hush"))
            .env("HUSH_PASSPHRASE", "pw")
            .stdin(Stdio::null());
        cmd
    }

    /// `hush run --secret DEMO_KEY -- sh -c script`, with `vars` for the script.
    fn run(&self, script: &str, vars: &[(&str, String)]) -> Command {
        let mut cmd = self.hush(&["run", "--secret", "DEMO_KEY", "--", "sh", "-c", script]);
        cmd.envs(vars.iter().map(|(k, v)| (k, v)));
        cmd
    }

    fn ok(&self, mut cmd: Command) -> Output {
        let out = cmd.output().unwrap();
        assert!(out.status.success(), "{cmd:?}: {out:?}");
        out
    }

    fn runs(&self) -> PathBuf {
        self.0.join(".config/hush/runs")
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// An HTTP server on this machine that answers every request with the
/// request's own head, and sends that head to the receiver too.
fn upstream() -> (u16, Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let mut head = String::new();
            let mut reader = BufReader::new(&stream);
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap() == 0 || line == "\r\n" {
                    break;
                }
                head.push_str(&line);
            }
            let _ = tx.send(head.clone());
            let reply = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{head}",
                head.len()
            );
            let _ = stream.write_all(reply.as_bytes());
        }
    });
    (port, rx)
}

fn received(rx: &Receiver<String>) -> String {
    rx.recv_timeout(Duration::from_secs(10))
        .expect("the request never reached the server")
}

const CURL: &str = r#"curl -sS -x "$HTTP_PROXY" -H "Authorization: Bearer $DEMO_KEY""#;

#[test]
fn child_sees_placeholders_and_only_the_bound_host_gets_the_key() {
    let (bound, bound_rx) = upstream();
    let (other, other_rx) = upstream();
    let home = Home::with_key("swap", bound);
    let script = format!(
        r#"echo "key=$DEMO_KEY"; env; {CURL} "http://127.0.0.1:$BOUND/"; {CURL} "http://127.0.0.1:$OTHER/""#
    );
    let out = home.ok(home.run(
        &script,
        &[("BOUND", bound.to_string()), ("OTHER", other.to_string())],
    ));
    let stdout = String::from_utf8(out.stdout).unwrap();

    let placeholder = stdout.lines().find_map(|l| l.strip_prefix("key=")).unwrap();
    assert!(placeholder.starts_with("hush_ph_"), "{stdout}");
    assert!(!stdout.contains(REAL), "the child saw the key: {stdout}");
    assert!(!stdout.contains("HUSH_PASSPHRASE"), "{stdout}");
    assert!(stdout.contains("HUSH_ACTIVE=1"), "{stdout}");

    let at_bound = received(&bound_rx);
    assert!(
        at_bound.contains(&format!("Bearer {REAL}\r\n")),
        "{at_bound}"
    );
    // The bound host's echo of the key came back to the child redacted.
    assert!(stdout.contains("Bearer HUSH_REDACTED"), "{stdout}");

    let at_other = received(&other_rx);
    assert!(
        at_other.contains(&format!("Bearer {placeholder}\r\n")),
        "{at_other}"
    );
}

/// With `--profile`, the profile's entry for a name is what reaches the
/// bound host; a profile the vault doesn't have warns and falls back.
#[test]
fn a_run_with_a_profile_sends_the_profile_key() {
    let (bound, rx) = upstream();
    let home = Home::with_key("profile", bound);
    let host = format!("127.0.0.1:{bound}");
    let mut add = home.hush(&[
        "secret",
        "add",
        "DEMO_KEY",
        "--host",
        &host,
        "--profile",
        "acme",
    ]);
    add.env("HUSH_SECRET_VALUE", "sk-acme-0123456789abcdef");
    home.ok(add);

    let run = |profile: &str| {
        let script = format!(r#"{CURL} -o /dev/null "http://127.0.0.1:$BOUND/""#);
        let mut cmd = home.hush(&[
            "run",
            "--profile",
            profile,
            "--secret",
            "DEMO_KEY",
            "--",
            "sh",
            "-c",
            &script,
        ]);
        cmd.env("BOUND", bound.to_string());
        let out = home.ok(cmd);
        (received(&rx), String::from_utf8(out.stderr).unwrap())
    };

    let (at_bound, stderr) = run("acme");
    assert!(
        at_bound.contains("Bearer sk-acme-0123456789abcdef\r\n"),
        "{at_bound}"
    );
    assert!(!stderr.contains("warning"), "{stderr}");

    let (at_bound, stderr) = run("acmee");
    assert!(
        at_bound.contains(&format!("Bearer {REAL}\r\n")),
        "{at_bound}"
    );
    assert!(
        stderr.contains("there is no profile acmee in the vault"),
        "{stderr}"
    );
}

/// A project mapped with `hush profile use` gets its profile from any
/// directory inside it, `--profile` overrides that, and a mapped project that
/// moved gets the unprofiled entries and a warning.
#[test]
fn a_mapped_project_runs_with_its_profile() {
    let (bound, rx) = upstream();
    let home = Home::with_key("mapped", bound);
    let host = format!("127.0.0.1:{bound}");
    let mut add = home.hush(&[
        "secret",
        "add",
        "DEMO_KEY",
        "--host",
        &host,
        "--profile",
        "acme",
    ]);
    add.env("HUSH_SECRET_VALUE", "sk-acme-0123456789abcdef");
    home.ok(add);
    let project = home.0.canonicalize().unwrap().join("project");
    let sub = project.join("sub");
    std::fs::create_dir_all(project.join(".git")).unwrap();
    std::fs::create_dir_all(&sub).unwrap();
    let mut map = home.hush(&["profile", "use", "acme"]);
    map.current_dir(&sub);
    home.ok(map);

    let run = |dir: &Path, flags: &[&str]| {
        let script = format!(r#"{CURL} -o /dev/null "http://127.0.0.1:$BOUND/""#);
        let mut args = vec!["run"];
        args.extend_from_slice(flags);
        args.extend(["--secret", "DEMO_KEY", "--", "sh", "-c", &script]);
        let mut cmd = home.hush(&args);
        cmd.current_dir(dir).env("BOUND", bound.to_string());
        let out = home.ok(cmd);
        (received(&rx), String::from_utf8(out.stderr).unwrap())
    };

    let (at_bound, stderr) = run(&sub, &[]);
    assert!(
        at_bound.contains("Bearer sk-acme-0123456789abcdef\r\n"),
        "{at_bound}"
    );
    assert!(
        stderr.contains(&format!(
            "using profile acme, mapped to {}",
            project.display()
        )),
        "{stderr}"
    );

    let (at_bound, stderr) = run(&sub, &["--profile", "beta"]);
    assert!(
        at_bound.contains(&format!("Bearer {REAL}\r\n")),
        "{at_bound}"
    );
    assert!(!stderr.contains("mapped to"), "{stderr}");

    // acme's last entry removed: the mapping stays, and falls back.
    home.ok(home.hush(&["secret", "rm", "DEMO_KEY", "--profile", "acme"]));
    let (at_bound, stderr) = run(&sub, &[]);
    assert!(
        at_bound.contains(&format!("Bearer {REAL}\r\n")),
        "{at_bound}"
    );
    assert!(
        stderr.contains(&format!(
            "{} is mapped to profile acme, which isn't in the vault",
            project.display()
        )),
        "{stderr}"
    );
    assert!(!stderr.contains("using profile acme"), "{stderr}");

    // Moved under the same name it's pointed out; elsewhere it isn't.
    let elsewhere = home.0.canonicalize().unwrap().join("elsewhere");
    let moved = elsewhere.join("project");
    std::fs::create_dir(&elsewhere).unwrap();
    std::fs::rename(&project, &moved).unwrap();
    let (_, stderr) = run(&elsewhere, &[]);
    assert!(!stderr.contains("no longer exists"), "{stderr}");
    let (at_bound, stderr) = run(&moved, &[]);
    assert!(
        at_bound.contains(&format!("Bearer {REAL}\r\n")),
        "{at_bound}"
    );
    assert!(
        stderr.contains(&format!(
            "{}, mapped to profile acme, no longer exists",
            project.display()
        )),
        "{stderr}"
    );
}

#[test]
fn exit_codes_pass_through() {
    let home = Home::new("exit");
    let code = |script: &str| {
        let mut cmd = home.hush(&["run", "--", "sh", "-c", script]);
        cmd.output().unwrap().status.code()
    };
    assert_eq!(code("exit 7"), Some(7));
    assert_eq!(code("kill -TERM $$"), Some(128 + libc::SIGTERM));
    // A nested run refuses to start, and its failure is the child's code.
    let nested = home
        .hush(&["run", "--", "sh", "-c", r#""$HUSH" run -- true"#])
        .output()
        .unwrap();
    assert_eq!(nested.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&nested.stderr).contains("already inside"),
        "{nested:?}"
    );
}

/// Ctrl-C reaches the whole foreground process group. The child decides what
/// it means; hush has to survive it and keep the proxy serving.
#[test]
fn ctrl_c_reaches_the_child_and_the_proxy_keeps_serving() {
    let (bound, rx) = upstream();
    let home = Home::with_key("ctrl-c", bound);
    let ready = home.0.join("ready");
    let script = format!(
        r#"trap 'echo interrupted' INT
{CURL} -o /dev/null "http://127.0.0.1:$BOUND/"
sleep 30 >/dev/null 2>&1 &
touch "$READY"
wait $!
kill $! 2>/dev/null
{CURL} "http://127.0.0.1:$BOUND/""#
    );
    let mut cmd = home.run(
        &script,
        &[
            ("BOUND", bound.to_string()),
            ("READY", ready.display().to_string()),
        ],
    );
    let child = cmd
        .process_group(0)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    received(&rx);
    wait_for(&ready);
    // As the terminal does: to every process in the group.
    assert_eq!(unsafe { libc::kill(-(child.id() as i32), libc::SIGINT) }, 0);

    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "{out:?}");
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.starts_with("interrupted\n"), "{stdout}");
    let after = received(&rx);
    assert!(after.contains(&format!("Bearer {REAL}\r\n")), "{after}");
}

/// A run's directory lives as long as the run. Directories of runs that died
/// without removing theirs are swept at the next start; a live pid's is kept.
#[test]
fn run_dirs_are_removed_and_dead_ones_swept() {
    let (bound, _rx) = upstream();
    let home = Home::with_key("sweep", bound);
    let runs = home.runs();
    let mut gone = Command::new("true").spawn().unwrap();
    let dead = runs.join(gone.id().to_string());
    gone.wait().unwrap();
    let alive = runs.join(std::process::id().to_string());
    for dir in [&dead, &alive] {
        std::fs::create_dir_all(dir).unwrap();
    }

    let out = home.ok(home.run(
        r#"test -f "$SSL_CERT_FILE" && test -f "$NODE_EXTRA_CA_CERTS" && dirname "$SSL_CERT_FILE""#,
        &[],
    ));
    let own = PathBuf::from(String::from_utf8(out.stdout).unwrap().trim_end());

    assert_eq!(own.parent(), Some(runs.as_path()), "{own:?}");
    assert!(!own.exists(), "the run's own directory outlived it");
    assert!(!dead.exists(), "a dead run's directory wasn't swept");
    assert!(alive.exists(), "a live pid's directory was swept");
}

fn wait_for(path: &Path) {
    let start = Instant::now();
    while !path.exists() {
        assert!(start.elapsed() < Duration::from_secs(30), "{path:?}");
        thread::sleep(Duration::from_millis(20));
    }
}
