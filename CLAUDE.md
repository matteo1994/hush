# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`hush` is a placeholder-swap credential proxy for AI coding agents: a child process only ever sees random placeholders in its env, and a loopback HTTP proxy swaps the placeholder for the real API key on the wire, only when the request is going to that secret's bound host. See README.md for the full design and threat model. Scope is deliberately narrow: static HTTP header credentials only (no DB creds, SSH, or request signing like SigV4).

## Commands

```bash
cargo build                 # debug build
cargo build --release
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test                  # proxy unit tests + in-process TLS end-to-end tests
cargo test <name>           # run a single test by name filter
```

CI (`.github/workflows/ci.yml`) runs `cargo fmt --check`, the clippy line above and `cargo test --locked` on Linux and macOS, using the toolchain from `rust-toolchain.toml`.

Versioning: `hush --version` prints the `Cargo.toml` version plus the commit it was built from, e.g. `hush 0.1.3 (93db286 2026-10-10)`, with `-dirty` after the hash for a tree with uncommitted changes (`build.rs` sets `HUSH_VERSION`). Don't bump the patch version or edit `CHANGELOG.md` in a PR: `.github/workflows/bump.yml` runs `.github/scripts/bump-version.sh` after every merge to master, which bumps the version, adds a `CHANGELOG.md` section listing the merged commits' subjects, commits both as `Release X.Y.Z` and tags `vX.Y.Z`. So the squash-merge subject is the changelog line: write it as a sentence a user would understand. For a minor or major release, change `version` in `Cargo.toml` (and `Cargo.lock`) in the PR; the workflow then releases that version instead of bumping.

Toolchain is pinned to nightly via `rust-toolchain.toml` (rustup). Unix-only (`PermissionsExt`, `ExitStatusExt`, `libc` signals). Rust edition 2024.

Manual end-to-end testing without interactive prompts: set `HUSH_PASSPHRASE` (used by every command that opens the vault) and `HUSH_SECRET_VALUE` (used by `secret add`). They operate on the real vault at `~/.config/hush/`, and there is no config-dir override, so point `HOME` at a throwaway directory such as `target/e2e`. `hush run` strips both variables from the child, so a nested `hush secret ...` inside it has to prompt, and fails with "no terminal" when there is none.

## Architecture

Single binary, no background process. Each command opens the vault itself.

- **CLI** (`main.rs`): `init`, and `secret add/bind/rm/ls`, which load the vault with the passphrase, mutate it, and `save_vault` it again (writes `vault.age.tmp`, then renames). Each load-modify-save holds `lock_vault` (an exclusive lock on `vault.lock`, a separate file because the rename replaces `vault.age`); reads don't lock. Mutations print what will change before prompting, and warn when `HUSH_ACTIVE` is set, i.e. when running inside `hush run`. `secret add` on an existing name lists its bindings and asks `[y/N]` on `/dev/tty` before the value prompt, unless `--force`; `secret bind` refuses a second binding for an env the secret already has (`SecretEntry::add_binding`).
- **Names** (`names.rs`): `collect` merges, in order and deduplicated, the `_KEY` names from the nearest `.env` (searched upward to the git root; outside a repo only the current directory), every name in `~/.config/hush/global.env`, and `--secret` flags. Shell-style `export NAME=` is accepted. This only scopes which placeholders a run gets. It isn't a security boundary.
- **`hush run`** (`run.rs`): prompts only if `names::collect` returned any names. It loads the vault, `mint`s a `hush_ph_<32 hex>` placeholder per matched name into a `PlaceholderEntry` table, and drops the vault, so only the named secrets stay in memory. Then it creates a `Mitm`, writes trust files into a private `RunDir` (`~/.config/hush/runs/<pid>/`, removed on drop; directories of runs whose pid no longer exists are swept at the next start), starts the proxy threads in-process, and spawns the child. After spawning it ignores SIGINT/SIGQUIT, so Ctrl-C reaches the child without killing the proxy. The child's exit code is passed through (`128+signal` if it was killed).
- **Proxy** (`proxy.rs`): forward proxy on `127.0.0.1:<random port>`, thread per connection. Plain HTTP (absolute-form URI or `Host` header) and intercepted HTTPS both go through `forward`: one request per connection, sent upstream with `Connection: close` and hop-by-hop headers stripped, body relayed by `Content-Length` or chunked framing, response relayed until upstream EOF. `CONNECT` to a host that some minted placeholder is bound to (`is_bound_host`) is intercepted; any other `CONNECT` is a blind TCP tunnel that is never decrypted. Swapping (`substitute_placeholders`) only happens when the header name matches the binding's `header` (case-insensitive), the header value exactly equals `format` with `{value}` → placeholder, and the target host string equals the binding's host (case-insensitive; port is not compared — for HTTPS the target is the `CONNECT` authority, not the inner `Host` header). Plain HTTP whose upstream peer address isn't loopback (`cleartext`) additionally needs the binding's `allow_http`. Otherwise the placeholder is forwarded verbatim — this silent pass-through is the core security property, don't turn it into an error. Requests to a bound host go out with `Accept-Encoding: identity`, and their responses pass through a `Scrubber` that replaces every real value with a same-length `HUSH_REDACTED***` marker (so framing stays valid), holding back the last `longest value − 1` bytes of each read so a value split across reads is still caught. Connection errors are never printed while the child runs (it owns the terminal); they are counted in an `ErrorLog` and `run` prints a summary after the child exits.
- **TLS** (`tls.rs`): `Mitm` holds a per-run CA whose key lives only in memory, plus cached per-host leaf `ServerConfig`s and the upstream `ClientConfig` (system roots via `rustls-native-certs`, `ring` provider, HTTP/1.1 ALPN only). `write_trust_files` writes `ca.pem` and `ca-bundle.pem` (system roots + CA) into the run's directory. Leaves need an Authority Key Identifier and ≤398-day validity, or OpenSSL strict mode (Python 3.13+) and Apple clients reject them.
- **Vault** (`vault.rs`): age scrypt-passphrase-encrypted JSON of `name → SecretEntry { value, bindings }`. Each `Binding` has `host`, optional `env`, `header` (default `Authorization`), `format` (default `Bearer {value}`), `allow_http` (default false). `find_binding` prefers an exact `--env` match, then falls back to an unscoped binding; a secret has at most one binding per env. Config dir and `runs/` are `0700`, the vault is `0600`.

### Child environment (`run::child_env`)

The parent env minus `HUSH_PASSPHRASE`/`HUSH_SECRET_VALUE`, plus:
- the placeholders;
- `HUSH_ACTIVE=1`, which makes a nested `hush run` refuse to start;
- with a proxy running: `HTTP(S)_PROXY` in both cases, `SSL_CERT_FILE`/`REQUESTS_CA_BUNDLE`/`CURL_CA_BUNDLE`/`GIT_SSL_CAINFO` pointing at the bundle, `NODE_EXTRA_CA_CERTS` pointing at the CA alone, and `NODE_USE_ENV_PROXY=1`.

## Invariants to preserve

- Real secret values must never enter a `hush run` child's environment, argv or stdout/stderr (`secret ls` prints bindings only).
- Every vault change must require the passphrase, and nothing may hand the passphrase or a decrypted vault to the child. That's what stops a child from rebinding a secret to a host it controls.
- Only bound hosts are ever intercepted, and the CA private key must never be written to disk.
