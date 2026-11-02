//! Apps started from inside their bundle, such as
//! `hush run -- "/Applications/Visual Studio Code.app/Contents/MacOS/Code"`.
//!
//! Such an app usually runs once per profile: a second launch hands itself to
//! the instance already running and exits. That instance was started without
//! this run's placeholders and proxy, so the launch would quietly use none of
//! them, and `hush run` would end with the launch, taking its proxy along.
//! Electron apps (VS Code, Cursor, Windsurf, Claude) keep one instance per
//! `--user-data-dir`, so a different one gets an instance of its own.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Result;
#[cfg(target_os = "macos")]
use anyhow::bail;

/// A launch that ends this soon, successfully, most likely handed itself to
/// a running instance; an app someone works in runs for minutes.
const HANDED_OFF_WITHIN: Duration = Duration::from_secs(10);

/// The file `program` runs, found the way the shell would find it and
/// through symlinks such as `/usr/local/bin/code`.
fn resolve(program: &str) -> Option<PathBuf> {
    let path = if program.contains('/') {
        PathBuf::from(program)
    } else {
        std::env::split_paths(&std::env::var_os("PATH")?)
            .map(|dir| dir.join(program))
            .find(|p| p.is_file())?
    };
    path.canonicalize().ok()
}

/// The app `exe` is the binary of: one in its bundle's `Contents/MacOS`. A
/// tool that ships inside a bundle, such as Docker's `docker` in
/// `Contents/Resources/bin`, is not the app, and may run any number of times.
fn app_of(exe: &Path) -> Option<PathBuf> {
    let bundle = bundle_of(exe)?;
    (exe.parent()? == bundle.join("Contents/MacOS")).then_some(bundle)
}

/// The app a launcher script in its bundle starts, such as VS Code's `code`
/// in `Contents/Resources/app/bin`. Scripts only: a compiled tool in a
/// bundle is more likely the tool itself.
fn launched_by(exe: &Path) -> Option<PathBuf> {
    let mut start = [0u8; 2];
    std::fs::File::open(exe).ok()?.read_exact(&mut start).ok()?;
    if &start != b"#!" {
        return None;
    }
    bundle_of(exe)
}

/// The outermost bundle `path` is in, since helpers live in bundles of their
/// own inside it.
fn bundle_of(path: &Path) -> Option<PathBuf> {
    let mut bundle = PathBuf::new();
    for part in path.components() {
        bundle.push(part);
        if bundle.extension().is_some_and(|e| e == "app") {
            return Some(bundle);
        }
    }
    None
}

/// The app's name, as the Dock shows it.
fn name(bundle: &Path) -> String {
    bundle
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| bundle.display().to_string())
}

/// The `--user-data-dir` in `args`, either spelling.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn user_data_dir(args: &[String]) -> Option<&str> {
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        if arg == "--user-data-dir" {
            return args.next().map(String::as_str);
        }
        if let Some(dir) = arg.strip_prefix("--user-data-dir=") {
            return Some(dir);
        }
    }
    None
}

/// The same directory, however it was spelled: the other process's relative
/// path can't be resolved, so that one compares as written.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn same_dir(a: Option<&str>, b: Option<&str>) -> bool {
    let resolve = |d: &str| Path::new(d).canonicalize().unwrap_or_else(|_| d.into());
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => resolve(a) == resolve(b),
        _ => false,
    }
}

/// Refuses to start `cmd` when it is an app's binary and that app already
/// runs with the same `--user-data-dir` (or both without one), since the
/// launch would be handed to it.
#[cfg(target_os = "macos")]
pub fn refuse_if_running(cmd: &[String]) -> Result<()> {
    let Some((program, args)) = cmd.split_first() else {
        return Ok(());
    };
    let Some(exe) = resolve(program) else {
        return Ok(());
    };
    let Some(bundle) = app_of(&exe) else {
        return Ok(());
    };
    let ours = user_data_dir(args);
    // The oldest is the app; a newer one can be a child it just forked,
    // which runs the same binary with the same arguments until it execs.
    let Some(pid) = procs::running(&exe)
        .into_iter()
        .filter(|(_, theirs)| same_dir(ours, user_data_dir(theirs)))
        .map(|(pid, _)| pid)
        .min()
    else {
        return Ok(());
    };
    let profile = match ours {
        Some(dir) => format!("with --user-data-dir {dir}"),
        None => "without --user-data-dir".into(),
    };
    bail!(
        "{} is already running {profile} (pid {pid}), and would take this launch over without \
         the placeholders or the proxy; quit it first, or give this one a --user-data-dir of its \
         own (VS Code and other Electron apps)",
        name(&bundle)
    )
}

#[cfg(not(target_os = "macos"))]
pub fn refuse_if_running(_cmd: &[String]) -> Result<()> {
    Ok(())
}

/// After `program` exited successfully within `elapsed`: says what most
/// likely happened when it is an app that came back that fast. Covers what
/// `refuse_if_running` can't see, such as a launcher script (`code`) that
/// returns once the window is open.
pub fn warn_if_handed_off(program: &str, elapsed: Duration) {
    if elapsed >= HANDED_OFF_WITHIN {
        return;
    }
    let Some(bundle) = resolve(program).and_then(|exe| app_of(&exe).or_else(|| launched_by(&exe)))
    else {
        return;
    };
    eprintln!(
        "hush: warning: {} returned after {}s. A launcher such as `code` returns once the window \
         is open, and an app that is already running takes the launch over; either way the app \
         has none of this run's placeholders or proxy now. Start the binary in {}/Contents/MacOS \
         instead, with a --user-data-dir of its own if the app is open.",
        name(&bundle),
        elapsed.as_secs(),
        bundle.display()
    );
}

/// Reads the process table: which processes run an executable, and with
/// which arguments.
#[cfg(target_os = "macos")]
mod procs {
    use std::path::{Path, PathBuf};

    /// The pids, other than this one, running `exe`, with their arguments.
    /// A process whose arguments can't be read (another user's) is left
    /// out: it can't be holding this user's profile.
    pub fn running(exe: &Path) -> Vec<(libc::pid_t, Vec<String>)> {
        let me = std::process::id() as libc::pid_t;
        pids()
            .into_iter()
            .filter(|&pid| pid != me && path(pid).as_deref() == Some(exe))
            .filter_map(|pid| Some((pid, super::parse_procargs(&procargs(pid)?)?)))
            .collect()
    }

    fn pids() -> Vec<libc::pid_t> {
        // SAFETY: a null buffer asks for the count; the second call fills at
        // most `pids.len()` entries, with room for processes started since.
        unsafe {
            let n = libc::proc_listallpids(std::ptr::null_mut(), 0);
            if n <= 0 {
                return Vec::new();
            }
            let mut pids = vec![0 as libc::pid_t; n as usize + 64];
            let size = (pids.len() * size_of::<libc::pid_t>()) as libc::c_int;
            let n = libc::proc_listallpids(pids.as_mut_ptr().cast(), size);
            pids.truncate(n.max(0) as usize);
            pids
        }
    }

    fn path(pid: libc::pid_t) -> Option<PathBuf> {
        let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
        // SAFETY: writes at most buf.len() bytes and returns how many.
        let n = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr().cast(), buf.len() as u32) };
        if n <= 0 {
            return None;
        }
        buf.truncate(n as usize);
        use std::os::unix::ffi::OsStringExt;
        Some(PathBuf::from(std::ffi::OsString::from_vec(buf)))
    }

    /// The raw `KERN_PROCARGS2` block: argc, the executable path, then the
    /// arguments and environment.
    fn procargs(pid: libc::pid_t) -> Option<Vec<u8>> {
        let mut max: libc::c_int = 0;
        let mut size = size_of::<libc::c_int>();
        let mut mib = [libc::CTL_KERN, libc::KERN_ARGMAX];
        // SAFETY: sysctl writes at most `size` bytes into the given buffer
        // and sets `size` to how many it wrote.
        unsafe {
            if libc::sysctl(
                mib.as_mut_ptr(),
                2,
                (&raw mut max).cast(),
                &mut size,
                std::ptr::null_mut(),
                0,
            ) != 0
            {
                return None;
            }
            let mut buf = vec![0u8; max.max(0) as usize];
            let mut size = buf.len();
            let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
            if libc::sysctl(
                mib.as_mut_ptr(),
                3,
                buf.as_mut_ptr().cast(),
                &mut size,
                std::ptr::null_mut(),
                0,
            ) != 0
            {
                return None;
            }
            buf.truncate(size);
            Some(buf)
        }
    }
}

/// The arguments in a `KERN_PROCARGS2` block, `argv[0]` first: a native
/// `int` argc, the executable path, NUL padding, then argc NUL-terminated
/// strings.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn parse_procargs(buf: &[u8]) -> Option<Vec<String>> {
    let argc = i32::from_ne_bytes(buf.get(..4)?.try_into().ok()?);
    let rest = &buf[4..];
    let exe_end = rest.iter().position(|&b| b == 0)?;
    let start = exe_end + rest[exe_end..].iter().position(|&b| b != 0)?;
    let args: Vec<String> = rest[start..]
        .split(|&b| b == 0)
        .take(usize::try_from(argc).ok()?)
        .map(|a| String::from_utf8_lossy(a).into_owned())
        .collect();
    (args.len() == argc as usize).then_some(args)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn finds_the_user_data_dir_in_either_spelling() {
        assert_eq!(
            user_data_dir(&strings(&["--user-data-dir", "/a"])),
            Some("/a")
        );
        assert_eq!(
            user_data_dir(&strings(&["-n", "--user-data-dir=/b"])),
            Some("/b")
        );
        assert_eq!(user_data_dir(&strings(&["--new-window"])), None);
        assert_eq!(user_data_dir(&strings(&["--user-data-dir"])), None);
    }

    #[test]
    fn no_dir_matches_no_dir_and_a_dir_matches_itself() {
        assert!(same_dir(None, None));
        assert!(!same_dir(Some("/a"), None));
        let tmp = std::env::temp_dir();
        let dotted = tmp.join(".");
        assert!(same_dir(tmp.to_str(), dotted.to_str()));
        assert!(!same_dir(Some("/a"), Some("/b")));
    }

    #[test]
    fn parses_a_procargs_block() {
        let mut buf = 2i32.to_ne_bytes().to_vec();
        buf.extend_from_slice(b"/Applications/X.app/Contents/MacOS/X\0\0\0\0");
        buf.extend_from_slice(b"X\0--user-data-dir=/d\0HOME=/Users/x\0");
        assert_eq!(
            parse_procargs(&buf),
            Some(strings(&["X", "--user-data-dir=/d"]))
        );
        // Fewer strings than argc says: not a block to trust.
        let mut short = 3i32.to_ne_bytes().to_vec();
        short.extend_from_slice(b"/x\0\0a\0");
        assert_eq!(parse_procargs(&short), None);
        assert_eq!(parse_procargs(b"\x01"), None);
    }

    #[test]
    fn only_an_apps_own_binary_or_launcher_script_counts() {
        let dir = std::env::temp_dir().join(format!("hush-app-{}", std::process::id()));
        let file = |rel: &str, body: &str| {
            let path = dir.join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, body).unwrap();
            resolve(path.to_str().unwrap()).unwrap()
        };
        let outer = file("Outer.app/Contents/MacOS/Outer", "\x7fELF");
        let helper = file(
            "Outer.app/Contents/Frameworks/Helper.app/Contents/MacOS/Helper",
            "",
        );
        let launcher = file("Outer.app/Contents/Resources/bin/outer", "#!/bin/sh\n");
        let tool = file("Outer.app/Contents/Resources/bin/tool", "\x7fELF");
        let plain = file("plain", "#!/bin/sh\n");
        let bundle = dir.canonicalize().unwrap().join("Outer.app");

        assert_eq!(app_of(&outer), Some(bundle.clone()));
        assert_eq!(name(&bundle), "Outer");
        assert_eq!(app_of(&helper), None);
        assert_eq!(app_of(&launcher), None);
        assert_eq!(launched_by(&launcher), Some(bundle));
        assert_eq!(app_of(&tool), None);
        assert_eq!(launched_by(&tool), None);
        assert_eq!(launched_by(&plain), None);
        assert_eq!(resolve(dir.join("missing").to_str().unwrap()), None);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
