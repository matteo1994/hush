# Changelog

Every merge to master that changes the program is a release. CI adds its entry
here, from the merged commits' subjects (see
`.github/scripts/bump-version.sh`).

## 0.1.24 (2026-10-24)

- Scrub a retired secret for a grace period after rotation. (#45)

## 0.1.23 (2026-10-24)

- Record when a secret was rotated, warn when it is overdue, and unbind a host (#44)

## 0.1.22 (2026-10-24)

- Rotate a secret's value in place, and change the vault passphrase (#43)

## 0.1.21 (2026-10-24)

- Scrub echoed secrets across chunks and encodings; reject unscannable bodies (#42)
- Push releases with a deploy key, so they get past master's ruleset. (#46)

## 0.1.20 (2026-10-20)

- Add profile use, a project runs with its own profile w/o --profile (#35)
- Document profiles: per-project keys under a shared name, how a project picks one, and what they don't protect. (#36)
- Replace the mile and TYPESAFE_API_KEY examples with generic ones (#38)
- README: install hush into a root-owned /opt/hush/bin as the threat model advises, and list the C compiler the build needs. (#37)
- Add SECURITY.md: how to report a vulnerability privately, which versions get fixes, and what counts. (#39)
- Build on stable Rust 1.99.0 instead of a nightly (#40)
- Run the tests on macOS in CI again, now that the repository is public. (#41)

## 0.1.19 (2026-10-19)

- Add --profile to run, profiles keys, unprofiled if nothing (#34)

## 0.1.18 (2026-10-19)

- Add --profile to secret add, bind, rm and ls, so a project can keep its own key under a shared name. (#33)

## 0.1.17 (2026-10-19)

- Test hush run end to end with the built binary: the key swap, Ctrl-C, exit codes and the run-dir sweep. (#31)
- Store profiles in the vault, and refuse to load a vault written by a newer hush instead of dropping what it doesn't know. (#32)

## 0.1.16 (2026-10-18)

- Pin a dated nightly in rust-toolchain.toml, so a new clippy lint can't fail CI without a code change. (#30)

## 0.1.15 (2026-10-17)

- Run CI tests on Linux only, since macOS minutes bill at 10x on a private repo. (#28)
- Update age to 0.12, which drops its unmaintained proc-macro-error2 dependency. (#27)

## 0.1.14 (2026-10-17)

- Update rustls to 0.23.46 and check dependencies for known advisories in CI. (#26)

## 0.1.13 (2026-10-17)

- Document that an older copy of the vault brings back removed keys and bindings. (#24)
- Warn before every passphrase prompt inside hush run, secret ls included. (#25)

## 0.1.12 (2026-10-17)

- Document that a key with permission to create keys can hand the agent a key hush can't redact. (#22)
- Keep a hush run child from attaching a debugger to hush or making it dump core. (#23)

## 0.1.11 (2026-10-17)

- Stop quoting a server's chunk-size line in errors printed after a run. (#21)

## 0.1.10 (2026-10-17)

- Test that a key a server echoes back is redacted on every response path. (#20)

## 0.1.9 (2026-10-17)

- Refuse a chunk line longer than 64 KiB instead of buffering it. (#19)

## 0.1.8 (2026-10-16)

- Treat a server at this machine's LAN address like a local one. (#18)

## 0.1.7 (2026-10-16)

- Send a key to a local server only at the address and port its binding names. (#17)

## 0.1.6 (2026-10-15)

- Refuse requests whose length a server could read differently, so hush and the server always agree where a request ends. (#16)

## 0.1.5 (2026-10-15)

- Send a key to a server on this machine only on the port its binding names. (#15)

## 0.1.4 (2026-10-14)

- Send the key only when the request names no host other than the bound one. (#14)

## 0.1.3 (2026-10-13)

- Keep intercepted HTTPS connections open, reusing one upstream connection per client connection. (#13)

## 0.1.2 (2026-10-12)

- Release only after the tests pass and only when the program changed; add the Apache-2.0 license. (#12)

## 0.1.1 (2026-10-12)

- Keep a changelog, written by CI with each release. (#11)

## 0.1.0 (2026-10-10)

- Initial commit: hush, a placeholder-swap credential proxy for AI coding agents.
- Add README documenting the design, usage, and v0 threat model.
- Clarify scope: HTTP(S) header-based API keys only, not DB/SSH/signing credentials.
- Pin nightly toolchain, add CLAUDE.md, drop unneeded deps (#1)
- HTTPS support via per-session CA interception of bound hosts (#2)
- Replace the background agent with a self-contained hush run. (#3)
- Add GitHub Actions CI (#4)
- Choose a run's secrets from .env upward, a global names file, and --secret. (#5)
- Swap over plain HTTP only to loopback, unless a binding opts in with --allow-http. (#6)
- Scrub real values from bound-host responses. (#7)
- Lock the vault during changes, confirm overwrites, one binding per env. (#8)
- Report proxy connection errors after the child exits, not over its screen. (#9)
- Add hush --version with the build commit, and bump the patch version on every merge. (#10)
