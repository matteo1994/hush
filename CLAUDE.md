# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`hush` is a placeholder-swap credential proxy for AI coding agents: a child process only ever sees random placeholders in its env, and a loopback HTTP proxy swaps the placeholder for the real API key on the wire, only when the request is going to that secret's bound host. See README.md for the full design and threat model. Scope is deliberately narrow: static HTTP header credentials only (no DB creds, SSH, or request signing like SigV4).

## Commands

```bash
cargo build                 # debug build
cargo build --release
cargo clippy
cargo test                  # no tests exist yet
cargo test <name>           # run a single test by name filter
```

Toolchain is pinned to nightly via `rust-toolchain.toml` (rustup). Unix-only (Unix domain sockets, `PermissionsExt`). Rust edition 2024.

Manual end-to-end testing without interactive prompts: set `HUSH_PASSPHRASE` (used by `init`/`unlock`) and `HUSH_SECRET_VALUE` (used by `secret add`). Note these operate on the real vault at `~/.config/hush/` — there is no config-dir override, so back up or move an existing vault before experimenting.

## Architecture

Single binary, two roles:

- **CLI client** (`main.rs`, `client.rs`): every `hush secret ...` and `hush run` call is a thin client that sends one JSON request line over the Unix socket `~/.config/hush/agent.sock` and reads one JSON response line. Only `init` and `unlock` touch the vault file directly.
- **`hush-agent`** (`agent.rs`): the long-lived process started by `hush unlock`. Holds the decrypted `Vault` and the passphrase in memory, serves the socket (thread per connection), and on every mutation re-encrypts and atomically rewrites the vault (`save_vault` writes `vault.age.tmp` then renames). It also starts the proxy.
- **Proxy** (`proxy.rs`): plain-HTTP forward proxy on `127.0.0.1:<random port>`, thread per connection, one request per connection. Handles absolute-form URIs or falls back to the `Host` header. Swapping (`substitute_placeholders`) only happens when the header name matches the binding's `header` (case-insensitive), the header value exactly equals `format` with `{value}` → placeholder, and the target host string equals the binding's host exactly (port is not compared). Otherwise the placeholder is forwarded verbatim — this silent pass-through is the core security property, don't turn it into an error.
- **Wire protocol** (`protocol.rs`): serde-tagged enums — `Request` tagged by `cmd`, `Response` tagged by `status`, both `snake_case`. Adding a command means touching `protocol.rs`, `agent::handle_request`, and the clap enums in `main.rs`.
- **Vault** (`vault.rs`): age scrypt-passphrase-encrypted JSON of `name → SecretEntry { value, bindings }`. Each `Binding` has `host`, optional `env`, `header` (default `Authorization`), `format` (default `Bearer {value}`). `find_binding` prefers an exact `--env` match, then falls back to an unscoped binding. Config dir is `0700`, vault and socket are `0600`.

### `hush run` flow

1. `find_managed_keys` scans `./.env` for names ending in `_KEY` (values ignored).
2. Sends `Mint { names, env }`; the agent generates a `hush_ph_<32 hex>` placeholder per matched name and records it in the shared `PlaceholderTable` (placeholders are never evicted for the agent's lifetime).
3. The child is spawned with `env_clear()` + the parent env + placeholders + `HTTP_PROXY`/`http_proxy`. Exit code is passed through.

## Invariants to preserve

- Real secret values must never enter a `hush run` child's environment, argv, stdout/stderr, or any `Response` sent to a client (`ListSecrets` returns bindings only).
- v0 is plain HTTP only; HTTPS (own CA + MITM cert generation) is the stated next step.
