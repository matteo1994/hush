use std::process::Command;

/// Bakes the commit a binary was built from into `hush --version`, e.g.
/// `0.1.3 (93db286 2026-10-10)`, with `-dirty` after the hash when the tree
/// had uncommitted changes. Outside a git checkout of hush itself it is the
/// bare version.
fn main() {
    let mut version = env!("CARGO_PKG_VERSION").to_string();
    if in_own_checkout()
        && let Some(hash) = git(&["rev-parse", "--short", "HEAD"])
    {
        let dirty = match git(&["status", "--porcelain"]) {
            Some(changes) if !changes.is_empty() => "-dirty",
            _ => "",
        };
        let date = git(&["log", "-1", "--format=%cs"]).unwrap_or_default();
        version.push_str(format!(" ({hash}{dirty} {date})").trim_end_matches(' '));
    }
    println!("cargo:rustc-env=HUSH_VERSION={version}");

    // The index changes on every commit, checkout and pull, HEAD on a switch.
    for file in ["HEAD", "index"] {
        if let Some(path) = git(&["rev-parse", "--git-path", file]) {
            println!("cargo:rerun-if-changed={path}");
        }
    }
    for path in ["build.rs", "src", "Cargo.toml", "Cargo.lock"] {
        println!("cargo:rerun-if-changed={path}");
    }
}

/// Whether this crate is the root of the git repository around it. Unpacked
/// inside someone else's repository, `git` would describe their commit, not
/// hush's.
fn in_own_checkout() -> bool {
    let Some(top) = git(&["rev-parse", "--show-toplevel"]) else {
        return false;
    };
    match (
        std::fs::canonicalize(top),
        std::fs::canonicalize(env!("CARGO_MANIFEST_DIR")),
    ) {
        (Ok(top), Ok(manifest)) => top == manifest,
        _ => false,
    }
}

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}
