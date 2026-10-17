# Changelog

Every merge to master that changes the program is a release. CI adds its entry
here, from the merged commits' subjects (see
`.github/scripts/bump-version.sh`).

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
