//! Which secret names a `hush run` asks for. Three sources, merged in order
//! and deduplicated:
//!
//! - the project's `.env`: `_KEY`-suffixed names only, since it usually
//!   holds other settings too;
//! - `~/.config/hush/global.env`: every name it lists, for secrets used by
//!   globally installed tools (e.g. `TYPESAFE_API_KEY` for `mile crew`);
//! - `--secret NAME` flags.
//!
//! None of this is a security boundary — any process in the project can
//! edit `.env`. It only scopes which placeholders a run hands out; what
//! protects a secret is its host binding.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

pub fn collect(cwd: &Path, global_file: &Path, flags: &[String]) -> Result<Vec<String>> {
    let mut names = Vec::new();
    if let Some(dotenv) = find_project_dotenv(cwd) {
        names.extend(dotenv_names(&read(&dotenv)?));
    }
    if global_file.is_file() {
        names.extend(global_names(&read(global_file)?));
    }
    names.extend(flags.iter().cloned());

    let mut seen = std::collections::HashSet::new();
    names.retain(|n| seen.insert(n.clone()));
    Ok(names)
}

fn read(path: &Path) -> Result<String> {
    fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))
}

/// The nearest `.env` from `start` upward, so `hush run` works from a
/// subdirectory. The search stops at the git root; outside a git repo only
/// `start` itself is checked, so an unrelated `.env` in some parent
/// directory is never picked up.
pub fn find_project_dotenv(start: &Path) -> Option<PathBuf> {
    let stop = project_dir(start);
    for dir in start.ancestors() {
        let candidate = dir.join(".env");
        if candidate.is_file() {
            return Some(candidate);
        }
        if dir == stop {
            break;
        }
    }
    None
}

/// The project `start` is in: the nearest directory holding `.git`, or
/// `start` itself outside a git repo.
pub fn project_dir(start: &Path) -> &Path {
    start
        .ancestors()
        .find(|dir| dir.join(".git").exists())
        .unwrap_or(start)
}

/// `_KEY`-suffixed names from a project `.env`. Values are ignored
/// entirely — hush never reads a real secret from `.env`.
fn dotenv_names(content: &str) -> Vec<String> {
    entries(content)
        .filter(|(_, assigned)| *assigned)
        .map(|(name, _)| name)
        .filter(|name| name.ends_with("_KEY"))
        .collect()
}

/// Every name in the global file, as `NAME=` or a bare `NAME`.
fn global_names(content: &str) -> Vec<String> {
    entries(content).map(|(name, _)| name).collect()
}

/// `(name, has_assignment)` per meaningful line, tolerating comments,
/// blank lines and shell-style `export NAME=...`.
fn entries(content: &str) -> impl Iterator<Item = (String, bool)> + '_ {
    content.lines().filter_map(|line| {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return None;
        }
        let line = line.strip_prefix("export ").map_or(line, str::trim_start);
        let (name, assigned) = match line.split_once('=') {
            Some((name, _)) => (name.trim(), true),
            None => (line, false),
        };
        let valid = !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        valid.then(|| (name.to_string(), assigned))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dotenv_takes_key_suffixed_names_only() {
        let dotenv = "# comment\n\nBILLING_API_KEY=\n  STRIPE_SECRET_KEY = sk_ignored\n\
                      export EXPORTED_KEY=x\nDATABASE_URL=postgres://\nKEYRING=x\nBARE_KEY\nnot a pair\n";
        assert_eq!(
            dotenv_names(dotenv),
            vec!["BILLING_API_KEY", "STRIPE_SECRET_KEY", "EXPORTED_KEY"]
        );
    }

    #[test]
    fn global_file_takes_every_name() {
        let global = "# tools\nTYPESAFE_API_KEY=\nGH_TOKEN\nexport OTHER=1\nnot a name\n";
        assert_eq!(
            global_names(global),
            vec!["TYPESAFE_API_KEY", "GH_TOKEN", "OTHER"]
        );
    }

    /// A throwaway directory tree, removed on drop.
    struct Tree(PathBuf);

    impl Tree {
        fn new(name: &str) -> Self {
            let root =
                std::env::temp_dir().join(format!("hush-names-{name}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&root);
            fs::create_dir_all(&root).unwrap();
            Tree(root)
        }

        fn dir(&self, rel: &str) -> PathBuf {
            let p = self.0.join(rel);
            fs::create_dir_all(&p).unwrap();
            p
        }

        fn file(&self, rel: &str, content: &str) -> PathBuf {
            let p = self.0.join(rel);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(&p, content).unwrap();
            p
        }
    }

    impl Drop for Tree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn dotenv_search_walks_up_to_the_git_root_and_no_further() {
        let t = Tree::new("walk");
        t.file("outside/.env", "OUTSIDE_KEY=\n");
        t.dir("outside/repo/.git");
        let root_env = t.file("outside/repo/.env", "ROOT_KEY=\n");
        let deep = t.dir("outside/repo/src/deep");

        assert_eq!(find_project_dotenv(&deep), Some(root_env.clone()));

        // Nearest wins.
        let nested = t.file("outside/repo/src/.env", "NESTED_KEY=\n");
        assert_eq!(find_project_dotenv(&deep), Some(nested));

        // A repo without its own .env never reaches the parent's.
        t.dir("outside/other/.git");
        let other_src = t.dir("outside/other/src");
        assert_eq!(find_project_dotenv(&other_src), None);
    }

    #[test]
    fn dotenv_search_outside_a_repo_checks_only_the_start_dir() {
        let t = Tree::new("norepo");
        t.file("parent/.env", "PARENT_KEY=\n");
        let child = t.dir("parent/child");
        assert_eq!(find_project_dotenv(&child), None);

        let own = t.file("parent/child/.env", "OWN_KEY=\n");
        assert_eq!(find_project_dotenv(&child), Some(own));
    }

    #[test]
    fn collect_merges_sources_in_order_without_duplicates() {
        let t = Tree::new("collect");
        t.dir("repo/.git");
        t.file("repo/.env", "PROJECT_KEY=\nSHARED_KEY=\n");
        let global = t.file("global.env", "SHARED_KEY=\nTYPESAFE_API_KEY=\n");
        let cwd = t.dir("repo/src");

        let names = collect(&cwd, &global, &["FLAG_KEY".into(), "PROJECT_KEY".into()]).unwrap();
        assert_eq!(
            names,
            vec!["PROJECT_KEY", "SHARED_KEY", "TYPESAFE_API_KEY", "FLAG_KEY"]
        );

        // A missing global file is fine.
        let names = collect(&cwd, &t.0.join("absent.env"), &[]).unwrap();
        assert_eq!(names, vec!["PROJECT_KEY", "SHARED_KEY"]);
    }
}
