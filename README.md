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

- **`hush secret add NAME --host HOST`**: register a secret and the one host it may be injected into. The binding lives with the secret in the vault, which is encrypted on disk (age, passphrase-based). Every vault change asks for the passphrase and shows what it's about to change first.
- **`hush run -- CMD...`**: asks for the passphrase and decrypts only the secrets the project's `.env` names. It then starts a loopback proxy inside itself and runs `CMD` as its child, with a random placeholder in place of each real value. `CMD`'s environment never contains the real bytes. When `CMD` makes a request through the proxy, `hush run` swaps the placeholder for the real value *on the wire*, but only if the request is going to that secret's bound host. A request to any other host gets the placeholder forwarded verbatim: no error, no side channel, just a normal auth failure from whatever it hit. When `CMD` exits, the decrypted secrets go with it.

That last part is the actual security property: even if an agent is prompt-injected into sending "the Authorization header" to an attacker's endpoint, there's nothing to send — the agent never had the real value, and the proxy refuses to hand it to an unauthorized destination.

### Which secrets get exposed to a given command

`hush run` doesn't take a list of secret names on the command line. Instead, it reads `.env` in the current directory and auto-detects any variable name ending in `_KEY`:

```bash
# .env — safe to commit, no real values live here
BILLING_API_KEY=
STRIPE_SECRET_KEY=
```

Each `_KEY`-suffixed name found there is cross-referenced against what's actually registered in the vault (filtered by `--env` if given); anything not registered is silently skipped, and anything registered but not listed in `.env` is never exposed to that project. `.env`'s value column is ignored entirely — the real value only ever lives in the vault.

### HTTPS

`hush run` sets `HTTPS_PROXY`/`https_proxy` alongside `HTTP_PROXY`. When a `CONNECT` targets a host that one of the minted placeholders is bound to, `hush run` intercepts it: it terminates TLS with a certificate for that host signed by a **per-run CA**, swaps the placeholder, and forwards the request over its own TLS connection to the real host, verified against the system trust store. `CONNECT`s to every other host get a blind byte tunnel. hush never decrypts traffic it has no secret for, and the placeholder in it goes out verbatim.

The CA is generated when `hush run` starts and its private key only ever exists in that process's memory. Nothing is added to the system keychain. Instead, `hush run` points the child at the CA through environment variables, using files in a private per-run directory under `~/.config/hush/runs/` that is removed when the run ends:

| Variable | Points at |
|---|---|
| `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO` | `ca-bundle.pem`: system roots plus the run's CA |
| `NODE_EXTRA_CA_CERTS` | `ca.pem`: the run's CA alone |

`NODE_USE_ENV_PROXY=1` is also set, so Node 24.5+ honors the proxy variables.

## Usage

```bash
# One-time setup
hush init                                   # create a new vault, set its passphrase

# Register a secret
hush secret add BILLING_API_KEY --host api.example.com

# Add another binding for a different environment
hush secret bind BILLING_API_KEY --host billing-staging.internal --env staging

hush secret ls                              # list names + bindings, never values
hush secret rm BILLING_API_KEY

# Run something with managed secrets in scope, none of them ever in its real form
hush run -- python billing_client.py
hush run --env staging -- ./deploy.sh
hush run -- claude                          # a coding agent and everything it starts
```

## Current scope (v0)

- **HTTP/1.1 to bound hosts.** Intercepted connections negotiate HTTP/1.1 only, and each request goes upstream with `Connection: close`. WebSocket upgrades to a bound host aren't supported.
- **The client must honor the proxy and CA variables above.** curl, Python (`urllib`, `requests`), OpenSSL-based tools and Node 24.5+ do. Clients that only read the OS keychain (for example Go binaries on macOS) or that pin certificates won't work against bound hosts, and fail with a TLS error instead of leaking anything.
- **One passphrase prompt per `hush run`.** There's no background agent: each `hush run` holds its own decrypted secrets and proxy for as long as its command runs. For the main use, `hush run -- claude`, that's one prompt per session. Ctrl-C goes to the command; `hush run` ignores it and stays up for as long as the command does.
- **No nesting.** A `hush run` inside another one refuses to start. The outer run's placeholders and proxy are already in place there.

## Threat model

**What this protects against:** an AI agent (or anything running as your own user) that reads env vars, inspects config files, or is prompt-injected into printing or exfiltrating "the API key" — because the real bytes are never in its reachable process tree in the first place. Also protects the value at rest: the vault file is encrypted, so directly reading it gets ciphertext.

**Changing where a secret may go needs the passphrase.** `secret add`/`bind`/`rm` decrypt and rewrite the vault themselves, so a process started by `hush run` can't rebind a secret to a host it controls. It never has the passphrase, and `hush run` strips `HUSH_PASSPHRASE` and `HUSH_SECRET_VALUE` from its environment. Run from inside `hush run`, those commands print a warning before prompting. Only type the passphrase for a change you started yourself.

**What this does not protect against:** something that can read the `hush run` process's own memory directly (rather than going through a normal file read) — this is a materially higher bar than the filesystem-based leaks it's designed to close, but it isn't a hard cryptographic guarantee. Real isolation (separate OS user, container, sandboxed agent execution) still strengthens this further and is complementary, not required.

**The per-run CA** can mint a certificate for any host, and the `hush run` child trusts it. Its key never leaves `hush run`'s memory and stops existing when the run ends, so this adds nothing an attacker could steal from disk. Anything that can read that memory could already read the secrets themselves. The CA files in the run directory are public certificates only.

**A bound host that echoes headers back** hands the real value to whatever reads the response. That's the case for request-inspection endpoints like postman-echo, and partly for error messages that quote the key. Only bind hosts you trust with the key.

**Automation escape hatches** (`HUSH_PASSPHRASE`, `HUSH_SECRET_VALUE` env vars, used instead of the interactive hidden prompt) exist for scripting/testing. They're less safe than the interactive prompt — the value becomes visible in the process environment — so avoid them for anything beyond local automation you control.

## Building

```bash
cargo build --release
```

No system dependencies beyond a Rust toolchain; all cryptography (`age`) and HTTP parsing are pure-Rust crates, so there's no equivalent of the "no prebuilt wheel for this platform" problem that motivated keeping this simple in the first place.
