# Changelog

Every merge to master that changes the program is a release. CI adds its entry
here, from the merged commits' subjects (see
`.github/scripts/bump-version.sh`).

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
