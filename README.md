# hush

A local, placeholder-swap credential proxy that keeps real API keys out of an AI coding agent's own context, memory, and transcript.

## Scope: HTTP(S) header-based API keys only

`hush` intercepts outbound HTTP requests and substitutes a header value (e.g. `Authorization: Bearer <placeholder>` → the real key) on the wire. That's the entire mechanism.

It does **not** handle, and has no path to handling without a fundamentally different mechanism:
- Database credentials (Postgres/MySQL/Mongo connection strings, etc.) — not an HTTP protocol, nothing to intercept as a header.
- SSH keys or any non-HTTP authentication.
- Request signing schemes where the credential isn't a static header value (AWS SigV4, HMAC-signed requests, etc.) — v0 only swaps a literal string into a literal header slot.

If a project needs those, `hush` isn't the tool — it's scoped narrowly on purpose, matching the exact class of leak (a Bearer/API-key header a coding agent can read or be tricked into exfiltrating) it was built to close.

## The problem

An AI coding agent that needs to call a billing/payments/whatever API needs the real API key *somewhere* it can reach. The usual options all put the real value directly in the agent's own reach: a `.env` file the agent can `Read`, a secrets manager that decrypts into the agent's own environment, a vault CLI the agent can call directly. Once the real value is in the agent's context — its env, its transcript, a file it can open — it can leak: through a prompt injection telling it to print or exfiltrate the key, or just through ordinary work (the agent reads a config file to debug something, and now the key is sitting in its own conversation history).

`hush` never lets that happen, structurally: the agent's own process never holds the real bytes at all, regardless of what it does or is tricked into doing.

## How it works

- **`hush unlock`** — run once per session (like `ssh-agent`). Prompts for a passphrase, decrypts your local vault into memory inside a small resident helper process (`hush-agent`), and starts a loopback HTTP proxy. The on-disk vault stays encrypted (age, passphrase-based) at all times; the decrypted secrets only ever exist in `hush-agent`'s own memory.
- **`hush secret add NAME --host HOST`** — register a secret and the one host it's allowed to be injected into. The binding (which host) lives with the secret, set once, not duplicated anywhere else.
- **`hush run -- CMD...`** — runs `CMD` with a random placeholder in place of each managed secret's real value. `CMD`'s own environment never contains the real bytes — only `hush-agent` does. When `CMD` makes an HTTP request through the proxy, `hush-agent` swaps the placeholder for the real value *on the wire*, but only if the request is going to that secret's bound host. A request to any other host gets the placeholder forwarded verbatim — no error, no side channel, just a normal auth failure from whatever it hit.

That last part is the actual security property: even if an agent is prompt-injected into sending "the Authorization header" to an attacker's endpoint, there's nothing to send — the agent never had the real value, and the proxy refuses to hand it to an unauthorized destination.

### Which secrets get exposed to a given command

`hush run` doesn't take a list of secret names on the command line. Instead, it reads `.env` in the current directory and auto-detects any variable name ending in `_KEY`:

```bash
# .env — safe to commit, no real values live here
BILLING_API_KEY=
STRIPE_SECRET_KEY=
```

Each `_KEY`-suffixed name found there is cross-referenced against what's actually registered in the vault (filtered by `--env` if given); anything not registered is silently skipped, and anything registered but not listed in `.env` is never exposed to that project. `.env`'s value column is ignored entirely — the real value only ever lives in the vault.

## Usage

```bash
# One-time setup
hush init                                   # create a new vault, set its passphrase
hush unlock                                 # start the session agent (leave running, e.g. `hush unlock &`)

# Register a secret
hush secret add BILLING_API_KEY --host api.example.com

# Add another binding for a different environment
hush secret bind BILLING_API_KEY --host billing-staging.internal --env staging

hush secret ls                              # list names + bindings, never values
hush secret rm BILLING_API_KEY

# Run something with managed secrets in scope, none of them ever in its real form
hush run -- python billing_client.py
hush run --env staging -- ./deploy.sh
```

## Current scope (v0)

- **Plain HTTP only.** No TLS interception yet — `HTTP_PROXY`/`http_proxy` only. HTTPS target support (own CA + cert generation) is the natural next step.
- **Foreground agent, no daemon.** `hush unlock` is a long-lived process you start yourself; there's no system service, no dedicated OS user, no `sudo` anywhere. Simpler than the alternative, at the cost of needing to keep a terminal/background job alive per session.
- **One passphrase prompt per session**, not per command. Everything after `hush unlock` — as many `hush run` invocations as you want — needs no further interaction.

## Threat model

**What this protects against:** an AI agent (or anything running as your own user) that reads env vars, inspects config files, or is prompt-injected into printing or exfiltrating "the API key" — because the real bytes are never in its reachable process tree in the first place. Also protects the value at rest: the vault file is encrypted, so directly reading it gets ciphertext.

**What this does not protect against:** something that can read `hush-agent`'s own process memory directly (rather than going through a normal file read) — this is a materially higher bar than the filesystem-based leaks it's designed to close, but it isn't a hard cryptographic guarantee. Real isolation (separate OS user, container, sandboxed agent execution) still strengthens this further and is complementary, not required.

**Automation escape hatches** (`HUSH_PASSPHRASE`, `HUSH_SECRET_VALUE` env vars, used instead of the interactive hidden prompt) exist for scripting/testing. They're less safe than the interactive prompt — the value becomes visible in the process environment — so avoid them for anything beyond local automation you control.

## Building

```bash
cargo build --release
```

No system dependencies beyond a Rust toolchain; all cryptography (`age`) and HTTP parsing are pure-Rust crates, so there's no equivalent of the "no prebuilt wheel for this platform" problem that motivated keeping this simple in the first place.
