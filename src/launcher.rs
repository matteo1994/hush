//! `hush app add`: a small `.app` in `~/Applications` that starts another app
//! under `hush run`, so it opens from the Dock or Spotlight, which start an
//! app with launchd's environment. `hush run -- open -a` can't do that: the
//! run would end as soon as `open` returns, taking the proxy along.
//!
//! The bundle is a shell script and a plist. It holds what a typed `hush run`
//! command would, and no secret: the run opens the vault itself, with Touch
//! ID when `hush keychain enable` saved the passphrase, since it has no
//! terminal to ask on. Nothing can see stderr either, so the script keeps it
//! in a log and shows hush's own lines in an alert when the run fails.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

use crate::{app, run};

/// Marks a bundle as one of ours, so `--force` never replaces anything else.
const ID_PREFIX: &str = "hush.launcher.";
const EXECUTABLE: &str = "hush-launcher";

/// What the launcher passes to `hush run`.
pub struct RunArgs<'a> {
    pub secrets: &'a [String],
    pub profile: Option<&'a str>,
    pub env: Option<&'a str>,
    pub args: &'a [String],
}

/// Writes the launcher for `app_name` (a name in an Applications folder, or
/// the path of a bundle) and returns where it went.
pub fn add(app_name: &str, run: &RunArgs, force: bool, home: &Path) -> Result<PathBuf> {
    // The launcher's working directory is `/`.
    if let Some(dir) = app::user_data_dir(run.args)
        && !Path::new(dir).is_absolute()
    {
        bail!("--user-data-dir {dir} must be an absolute path, as a launcher runs from /");
    }
    let bundle = find_app(app_name, home)?;
    if is_launcher(&bundle) {
        bail!("{} is itself a hush launcher", bundle.display());
    }
    let plist = bundle.join("Contents/Info.plist");
    let executable = plist_value(&plist, "CFBundleExecutable")
        .with_context(|| format!("{} names no executable", plist.display()))?;
    let binary = bundle.join("Contents/MacOS").join(executable);
    if !binary.is_file() {
        bail!("{} doesn't exist", binary.display());
    }

    let name = app::name(&bundle);
    let folder = home.join("Applications");
    let dest = folder.join(format!("{name} (hush).app"));
    if dest.exists() {
        if !is_launcher(&dest) {
            bail!(
                "{} exists and isn't a hush launcher; move it first",
                dest.display()
            );
        }
        if !force {
            bail!("{} exists; --force replaces it", dest.display());
        }
    }

    // Built beside the destination, so a failure leaves any old one in place.
    let tmp = folder.join(format!(".{name} (hush).app.tmp"));
    let _ = fs::remove_dir_all(&tmp);
    let written = write_bundle(&tmp, &name, &bundle, &binary, run).and_then(|()| {
        replace_bundle(&tmp, &dest, &folder.join(format!(".{name} (hush).app.old")))
    });
    if written.is_err() {
        let _ = fs::remove_dir_all(&tmp);
    }
    written.with_context(|| format!("writing {}", dest.display()))?;
    Ok(dest)
}

/// Whether `bundle` is one `add` wrote.
fn is_launcher(bundle: &Path) -> bool {
    plist_value(&bundle.join("Contents/Info.plist"), "CFBundleIdentifier")
        .is_some_and(|id| id.starts_with(ID_PREFIX))
}

/// The bundle's icon file in `Contents/Resources`. Newer apps may only have
/// an asset catalog, which `None` leaves the launcher without.
fn icon_file(bundle: &Path) -> Option<String> {
    let icon = plist_value(&bundle.join("Contents/Info.plist"), "CFBundleIconFile")?;
    let file = if Path::new(&icon).extension().is_some() {
        icon
    } else {
        format!("{icon}.icns")
    };
    bundle
        .join("Contents/Resources")
        .join(&file)
        .is_file()
        .then_some(file)
}

/// The launcher's files, in `tmp`.
fn write_bundle(tmp: &Path, name: &str, bundle: &Path, binary: &Path, run: &RunArgs) -> Result<()> {
    let icon = icon_file(bundle);
    fs::create_dir_all(tmp.join("Contents/MacOS"))?;
    fs::write(
        tmp.join("Contents/Info.plist"),
        info_plist(name, icon.as_deref()),
    )?;
    let script_path = tmp.join("Contents/MacOS").join(EXECUTABLE);
    let hush = std::env::current_exe()?;
    fs::write(&script_path, script(name, &hush, binary, run))?;
    fs::set_permissions(&script_path, fs::Permissions::from_mode(0o755))?;
    if let Some(icon) = &icon {
        fs::create_dir_all(tmp.join("Contents/Resources"))?;
        fs::copy(
            bundle.join("Contents/Resources").join(icon),
            tmp.join("Contents/Resources").join(icon),
        )?;
    }
    Ok(())
}

/// A path as given, or `NAME.app` in the folders apps are installed to.
fn find_app(app: &str, home: &Path) -> Result<PathBuf> {
    if app.contains('/') {
        let path = Path::new(app);
        if !path.join("Contents/Info.plist").is_file() {
            bail!("{app} isn't an app bundle");
        }
        return Ok(path.canonicalize()?);
    }
    let file = if app.ends_with(".app") {
        app.to_string()
    } else {
        format!("{app}.app")
    };
    [Path::new("/Applications"), &home.join("Applications")]
        .iter()
        .map(|folder| folder.join(&file))
        .find(|path| path.join("Contents/Info.plist").is_file())
        .with_context(|| {
            format!(
                "no {file} in /Applications or {}; give the path of the app instead",
                home.join("Applications").display()
            )
        })
}

/// A key of a plist, XML or binary.
fn plist_value(plist: &Path, key: &str) -> Option<String> {
    let out = Command::new("/usr/bin/plutil")
        .args(["-extract", key, "raw", "-o", "-"])
        .arg(plist)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let value = String::from_utf8(out.stdout).ok()?;
    Some(value.trim_end_matches('\n').to_string())
}

/// Moves `tmp` to `dest`, putting back whatever was at `dest` if that fails.
fn replace_bundle(tmp: &Path, dest: &Path, old: &Path) -> Result<()> {
    let _ = fs::remove_dir_all(old);
    if dest.exists() {
        fs::rename(dest, old)?;
    }
    if let Err(e) = fs::rename(tmp, dest) {
        let _ = fs::rename(old, dest);
        return Err(e.into());
    }
    let _ = fs::remove_dir_all(old);
    Ok(())
}

/// A short hash of `name` that is the same in every build, unlike
/// `DefaultHasher`: FNV-1a.
fn stable_hash(name: &str) -> u32 {
    name.bytes().fold(0x811c_9dc5, |hash: u32, byte| {
        (hash ^ u32::from(byte)).wrapping_mul(0x0100_0193)
    })
}

/// `LSUIElement` keeps the launcher out of the Dock: it never checks in as an
/// app, so its icon would bounce beside the real app's.
fn info_plist(name: &str, icon: Option<&str>) -> String {
    let slug: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    // Names can share a slug, and LaunchServices treats bundles with one id
    // as one app.
    let hash = stable_hash(name);
    let title = xml_escape(&format!("{name} (hush)"));
    let icon = icon.map_or(String::new(), |icon| {
        format!(
            "  <key>CFBundleIconFile</key><string>{}</string>\n",
            xml_escape(icon)
        )
    });
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleExecutable</key><string>{EXECUTABLE}</string>
  <key>CFBundleIdentifier</key><string>{ID_PREFIX}{slug}-{hash:08x}</string>
  <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
  <key>CFBundleName</key><string>{title}</string>
  <key>CFBundlePackageType</key><string>APPL</string>
{icon}  <key>LSUIElement</key><true/>
</dict>
</plist>
"#
    )
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// The launcher itself. Everything that came from outside is single-quoted,
/// and what the alert shows is passed as an argument, never as AppleScript.
/// It waits for the run rather than `exec`ing it, to report how it ended.
fn script(name: &str, hush: &Path, binary: &Path, run: &RunArgs) -> String {
    let mut command = vec!["\"$hush\"".to_string(), "run".to_string()];
    for secret in run.secrets {
        command.extend(["--secret".to_string(), quote(secret)]);
    }
    if let Some(profile) = run.profile {
        command.extend(["--profile".to_string(), quote(profile)]);
    }
    if let Some(env) = run.env {
        command.extend(["--env".to_string(), quote(env)]);
    }
    command.extend(["--".to_string(), quote(&binary.to_string_lossy())]);
    command.extend(run.args.iter().map(|arg| quote(arg)));
    let command = command.join(" ");
    let title = quote(&format!("{name} under hush"));
    let hush = quote(&hush.to_string_lossy());
    let log = quote(&format!("{name}.log"));
    let own_failure = run::OWN_FAILURE;
    format!(
        r#"#!/bin/sh
# Written by `hush app add`. It holds no secret: `hush run` opens the vault.
title={title}
hush={hush}
logs="$HOME/Library/Logs/hush"
log="$logs/"{log}

alert() {{
  osascript -e 'on run argv' \
    -e 'display alert (item 1 of argv) message (item 2 of argv) as critical' \
    -e 'end run' "$title" "$1" >/dev/null 2>&1
}}

if [ ! -x "$hush" ]; then
  alert "There is no hush at $hush any more. Run hush app add again with --force."
  exit 127
fi
mkdir -p "$logs"
(umask 077; : >"$log")
{command} >"$log" 2>&1
code=$?
if [ "$code" -eq {own_failure} ]; then
  why=$(grep '^hush: ' "$log" | tail -n 3)
  [ -z "$why" ] || alert "$why"
fi
exit "$code"
"#
    )
}

fn quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_for_the_shell() {
        assert_eq!(quote("a b"), "'a b'");
        assert_eq!(quote("it's $HOME"), r"'it'\''s $HOME'");
    }

    #[test]
    fn nothing_from_outside_reaches_the_script_unquoted() {
        let secrets = ["KEY$(touch x)".to_string()];
        let args = ["--flag;id".to_string()];
        let run = RunArgs {
            secrets: &secrets,
            profile: Some("work`id`"),
            env: None,
            args: &args,
        };
        let name = "A'pp\nrm -rf x";
        let text = script(name, Path::new("/h ush"), Path::new("/a b/C"), &run);
        assert!(text.contains(r"'KEY$(touch x)'"), "{text}");
        assert!(text.contains("'work`id`'"), "{text}");
        assert!(text.contains("'--flag;id'"), "{text}");
        assert!(text.contains("hush='/h ush'"), "{text}");
        assert!(text.contains(r"title='A'\''pp"), "{text}");
    }

    #[test]
    fn the_plist_is_escaped_and_stays_out_of_the_dock() {
        let text = info_plist("R&D <x>", Some("a.icns"));
        assert!(
            text.contains("<string>R&amp;D &lt;x&gt; (hush)</string>"),
            "{text}"
        );
        assert!(text.contains("<string>hush.launcher.R-D--x--"), "{text}");
        assert!(text.contains("<key>LSUIElement</key><true/>"), "{text}");
        assert!(text.contains("<string>a.icns</string>"), "{text}");
    }

    #[test]
    fn names_with_one_slug_get_different_ids() {
        let id = |name| info_plist(name, None);
        assert_ne!(id("R&D"), id("R D"));
        assert_eq!(stable_hash("Cursor"), stable_hash("Cursor"));
        // Pinned: a launcher's id must not change between builds.
        assert_eq!(stable_hash("a"), 0xe40c_292c);
    }

    #[test]
    fn a_relative_user_data_dir_is_refused() {
        let args = ["--user-data-dir".to_string(), "dir".to_string()];
        let run = RunArgs {
            secrets: &[],
            profile: None,
            env: None,
            args: &args,
        };
        let err = add("Nothing", &run, false, Path::new("/nonexistent")).unwrap_err();
        assert!(err.to_string().contains("absolute"), "{err}");
    }

    #[test]
    fn a_missing_app_names_where_it_looked() {
        let run = RunArgs {
            secrets: &[],
            profile: None,
            env: None,
            args: &[],
        };
        let err = add("No Such App", &run, false, Path::new("/nonexistent")).unwrap_err();
        assert!(err.to_string().contains("/Applications"), "{err}");
    }
}
