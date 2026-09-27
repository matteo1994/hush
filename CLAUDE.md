# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`hush` is a placeholder-swap credential proxy for AI coding agents: a child process only ever sees random placeholders in its env, and a loopback HTTP proxy swaps the placeholder for the real API key on the wire, only when the request is going to that secret's bound host. See README.md for the full design and threat model. Scope is deliberately narrow: static HTTP header credentials only (no DB creds, SSH, or request signing like SigV4).

## Commands

```bash
cargo build                 # debug build
cargo build --release
cargo clippy
cargo test                  # proxy unit tests + in-process TLS end-to-end tests
cargo test <name>           # run a single test by name filter
```

Toolchain is pinned to nightly via `rust-toolchain.toml` (rustup). Unix-only (Unix domain sockets, `PermissionsExt`). Rust edition 2024.

Manual end-to-end testing without interactive prompts: set `HUSH_PASSPHRASE` (used by `init`/`unlock`) and `HUSH_SECRET_VALUE` (used by `secret add`). Note these operate on the real vault at `~/.config/hush/` — there is no config-dir override, so point `HOME` at a throwaway directory. Keep that path short: macOS caps Unix socket paths at 104 bytes, and a too-long `agent.sock` path makes `hush unlock` fail silently.

## Architecture

Single binary, two roles:

- **CLI client** (`main.rs`, `client.rs`): every `hush secret ...` and `hush run` call is a thin client that sends one JSON request line over the Unix socket `~/.config/hush/agent.sock` and reads one JSON response line. Only `init` and `unlock` touch the vault file directly.
- **`hush-agent`** (`agent.rs`): the long-lived process started by `hush unlock`. Holds the decrypted `Vault` and the passphrase in memory, serves the socket (thread per connection), and on every mutation re-encrypts and atomically rewrites the vault (`save_vault` writes `vault.age.tmp` then renames). It also starts the proxy.
- **Proxy** (`proxy.rs`): forward proxy on `127.0.0.1:<random port>`, thread per connection. Plain HTTP (absolute-form URI or `Host` header) and intercepted HTTPS both go through `forward`: one request per connection, sent upstream with `Connection: close` and hop-by-hop headers stripped, body relayed by `Content-Length` or chunked framing, response relayed until upstream EOF. `CONNECT` to a host that some minted placeholder is bound to (`is_bound_host`) is intercepted; any other `CONNECT` is a blind TCP tunnel that is never decrypted. Swapping (`substitute_placeholders`) only happens when the header name matches the binding's `header` (case-insensitive), the header value exactly equals `format` with `{value}` → placeholder, and the target host string equals the binding's host (case-insensitive; port is not compared — for HTTPS the target is the `CONNECT` authority, not the inner `Host` header). Otherwise the placeholder is forwarded verbatim — this silent pass-through is the core security property, don't turn it into an error.
- **TLS** (`tls.rs`): `Mitm` holds a per-session CA generated at `hush unlock`, whose key lives only in memory, plus cached per-host leaf `ServerConfig`s and the upstream `ClientConfig` (system roots via `rustls-native-certs`, `ring` provider, HTTP/1.1 ALPN only). `write_trust_files` writes `ca.pem` and `ca-bundle.pem` (system roots + CA) to the config dir. Leaves need an Authority Key Identifier and ≤398-day validity, or OpenSSL strict mode (Python 3.13+) and Apple clients reject them.
- **Wire protocol** (`protocol.rs`): serde-tagged enums — `Request` tagged by `cmd`, `Response` tagged by `status`, both `snake_case`. Adding a command means touching `protocol.rs`, `agent::handle_request`, and the clap enums in `main.rs`.
- **Vault** (`vault.rs`): age scrypt-passphrase-encrypted JSON of `name → SecretEntry { value, bindings }`. Each `Binding` has `host`, optional `env`, `header` (default `Authorization`), `format` (default `Bearer {value}`). `find_binding` prefers an exact `--env` match, then falls back to an unscoped binding. Config dir is `0700`, vault and socket are `0600`.

### `hush run` flow

1. `find_managed_keys` scans `./.env` for names ending in `_KEY` (values ignored).
2. Sends `Mint { names, env }`; the agent generates a `hush_ph_<32 hex>` placeholder per matched name and records it in the shared `PlaceholderTable` (placeholders are never evicted for the agent's lifetime).
3. The child is spawned with `env_clear()` + the parent env + placeholders + proxy vars (`HTTP(S)_PROXY`, both cases) + CA trust vars (`SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO` → bundle; `NODE_EXTRA_CA_CERTS` → CA only; `NODE_USE_ENV_PROXY=1`). Exit code is passed through.

## Invariants to preserve

- Real secret values must never enter a `hush run` child's environment, argv, stdout/stderr, or any `Response` sent to a client (`ListSecrets` returns bindings only).
- Only bound hosts are ever intercepted, and the CA private key must never be written to disk or sent to a client.
