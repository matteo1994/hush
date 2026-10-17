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

- **`hush secret add NAME --host HOST`**: register a secret and the one host it may be injected into. The binding lives with the secret in the vault, which is encrypted on disk (age, passphrase-based). Every vault change asks for the passphrase and shows what it's about to change first. Adding a name that already exists asks before replacing it (`--force` skips the question), and a secret gets at most one binding per environment. Vault changes take a lock, so two running at once can't lose each other's edits.
- **`hush run -- CMD...`**: asks for the passphrase and decrypts only the secrets the project's `.env` names. It then starts a loopback proxy inside itself and runs `CMD` as its child, with a random placeholder in place of each real value. `CMD`'s environment never contains the real bytes. When `CMD` makes a request through the proxy, `hush run` swaps the placeholder for the real value *on the wire*, but only if the request is going to that secret's bound host. A request to any other host gets the placeholder forwarded verbatim: no error, no side channel, just a normal auth failure from whatever it hit. When `CMD` exits, the decrypted secrets go with it.

That last part is the actual security property: even if an agent is prompt-injected into sending "the Authorization header" to an attacker's endpoint, there's nothing to send — the agent never had the real value, and the proxy refuses to hand it to an unauthorized destination.

### Which secrets get exposed to a given command

A `hush run` gets a placeholder for every name from three sources:

1. **The project's `.env`**: names ending in `_KEY`, since `.env` usually holds other settings too. hush looks in the current directory and then upward to the git root, so it works from subdirectories. Outside a git repo it checks only the current directory.

   ```bash
   # .env — safe to commit, no real values live here
   BILLING_API_KEY=
   export STRIPE_SECRET_KEY=
   ```

2. **`~/.config/hush/global.env`**: every name it lists, in every `hush run`, wherever it starts. This is for secrets that belong to a globally installed tool rather than a project, such as `TYPESAFE_API_KEY` for `mile crew`.

3. **`--secret NAME`** (repeatable), for one-off commands: `hush run --secret TYPESAFE_API_KEY -- mile crew judge`.

Each name is looked up in the vault (filtered by `--env` if given). Names with no matching binding are skipped with a warning. Value columns are ignored entirely: the real value only ever lives in the vault. If no source names anything, `hush run` doesn't ask for the passphrase at all.

None of this is a security boundary. Any process in the project can edit `.env`, so it only decides which placeholders a run hands out. What protects a secret is its host binding: a placeholder only becomes the real value on the way to that host.

### HTTPS

`hush run` sets `HTTPS_PROXY`/`https_proxy` alongside `HTTP_PROXY`. When a `CONNECT` targets a host that one of the minted placeholders is bound to, `hush run` intercepts it: it terminates TLS with a certificate for that host signed by a **per-run CA**, swaps the placeholder, and forwards the request over its own TLS connection to the real host, verified against the system trust store. A request on that connection that names a different host, in its `Host` header or in a full URL on the request line, keeps its placeholder: a server shared between many sites, such as a CDN, would otherwise deliver the key to whichever site the request named. `CONNECT`s to every other host get a blind byte tunnel. hush never decrypts traffic it has no secret for, and the placeholder in it goes out verbatim.

The CA is generated when `hush run` starts and its private key only ever exists in that process's memory. Nothing is added to the system keychain. Instead, `hush run` points the child at the CA through environment variables, using files in a private per-run directory under `~/.config/hush/runs/` that is removed when the run ends:

| Variable | Points at |
|---|---|
| `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO` | `ca-bundle.pem`: system roots plus the run's CA |
| `NODE_EXTRA_CA_CERTS` | `ca.pem`: the run's CA alone |

`NODE_USE_ENV_PROXY=1` is also set, so Node 24.5+ honors the proxy variables.

### Plain HTTP

A plain-HTTP request to a bound host only gets the real value when the proxy's upstream connection is to this machine, such as a local dev server. Anywhere else the key would cross the network unencrypted, so the placeholder goes out verbatim instead. To allow that for a host you trust anyway, such as one on a private network, bind it with `--allow-http`.

### Ports

`--host` can name a port, such as `--host api.example.com:8443`; the real value then goes only to that port. Without one, any port of the bound host will do.

A server on your own machine needs its address and port, such as `--host 127.0.0.1:3000` or `--host '[::1]:3000'`, whichever it listens on. Any program there, including the agent, can listen on another port, or on the same port in the other address family: `localhost` means both `127.0.0.1` and `::1`. The key then only goes to that exact socket, whatever name the request uses, so clients can keep calling `localhost:3000`. The same goes for the machine's other addresses, such as its LAN address: bind `192.168.1.5:3000`, not `192.168.1.5` or `mymac.local`, which hush never sends to once it finds the connection leads back to this machine. `secret add` and `secret bind` refuse `localhost` or a loopback address without a port, and `hush run` warns about such a binding made before, which is never sent.

## Usage

```bash
# One-time setup
hush init                                   # create a new vault, set its passphrase

# Register a secret
hush secret add BILLING_API_KEY --host api.example.com

# Add another binding for a different environment
hush secret bind BILLING_API_KEY --host billing-staging.internal --env staging --allow-http
hush secret bind BILLING_API_KEY --host 127.0.0.1:3000 --env dev  # a local dev server

hush secret ls                              # list names + bindings, never values
hush secret rm BILLING_API_KEY

# Run something with managed secrets in scope, none of them ever in its real form
hush run -- python billing_client.py
hush run --secret TYPESAFE_API_KEY -- mile crew judge   # a secret not listed in any .env
hush run --env staging -- ./deploy.sh
hush run -- claude                          # a coding agent and everything it starts
```

## Current scope (v0)

- **HTTP/1.1 to bound hosts.** Intercepted connections negotiate HTTP/1.1 only, not HTTP/2. A client that keeps its connection open gets one upstream connection for as long as it does, so repeated requests skip the TLS handshake; plain HTTP is still one request per connection. WebSocket upgrades to a bound host aren't supported.
- **The client must honor the proxy and CA variables above.** curl, Python (`urllib`, `requests`), OpenSSL-based tools and Node 24.5+ do. Clients that only read the OS keychain (for example Go binaries on macOS) or that pin certificates won't work against bound hosts, and fail with a TLS error instead of leaking anything.
- **One passphrase prompt per `hush run`.** There's no background agent: each `hush run` holds its own decrypted secrets and proxy for as long as its command runs. For the main use, `hush run -- claude`, that's one prompt per session. Ctrl-C goes to the command; `hush run` ignores it and stays up for as long as the command does.
- **No nesting.** A `hush run` inside another one refuses to start. The outer run's placeholders and proxy are already in place there.

## Threat model

**What this protects against:** an AI agent (or anything running as your own user) that reads env vars, inspects config files, or is prompt-injected into printing or exfiltrating "the API key" — because the real bytes are never in its reachable process tree in the first place. Also protects the value at rest: the vault file is encrypted, so directly reading it gets ciphertext.

**Changing where a secret may go needs the passphrase.** `secret add`/`bind`/`rm` decrypt and rewrite the vault themselves, so a process started by `hush run` can't rebind a secret to a host it controls. It never has the passphrase, and `hush run` strips `HUSH_PASSPHRASE` and `HUSH_SECRET_VALUE` from its environment. Run from inside `hush run`, those commands print a warning before prompting. Only type the passphrase for a change you started yourself.

**Reading `hush run`'s memory.** The decrypted values live in `hush run`'s memory for as long as its command runs, and the command runs as the same user. Left alone, a same-user process could get them out: on macOS `lldb -p <pid>` attaches to `hush run` without a prompt and can save a core holding every value; on Linux `/proc/<pid>/mem` and ptrace are open to the same user unless Yama restricts them, and even then the child can raise hush's core limit (`prlimit`), kill it with SIGABRT and read the dump with `coredumpctl`. So every hush command shuts that off for itself before anything is decrypted. On Linux it makes itself non-dumpable (`PR_SET_DUMPABLE`), which closes ptrace, `/proc/<pid>/mem` and core dumps to the same user. On macOS it refuses debugger attach (`PT_DENY_ATTACH`) and sets its core-dump limit to 0; the child gets back the limit hush started with, and stays debuggable itself. That doesn't stop root. On macOS it also doesn't stop a program allowed to take another process's task port, which needs Developer Mode or `DevToolsSecurity -enable` and reads memory without attaching; signing hush with the hardened runtime refuses those too: `codesign -f -s - -o runtime "$(command -v hush)"`, again after each install. Real isolation (separate OS user, container, sandboxed agent execution) still strengthens this further and is complementary, not required.

**The files in `~/.config/hush`** belong to your user, so a `hush run` child can delete, replace or lock any of them. Without the passphrase it can't read the vault or make one hush accepts, but it can put back an older copy of `vault.age`, and that brings back every secret and binding the copy had. So `secret rm`, or taking a host off a key, only changes this vault file: if you no longer trust a host with a key, revoke the key at the vendor too. The other files carry nothing to steal. `global.env` only names which secrets a run gets placeholders for, and the run directories hold public certificates. Deleting or locking them, or the vault, makes hush commands fail or wait; it doesn't leak anything.

**The per-run CA** can mint a certificate for any host, and the `hush run` child trusts it. Its key never leaves `hush run`'s memory and stops existing when the run ends, so this adds nothing an attacker could steal from disk. Anything that can read that memory could already read the secrets themselves. The CA files in the run directory are public certificates only.

**A bound host that echoes the key back**, such as a request-inspection endpoint like postman-echo or an error message that quotes it, is mostly covered. hush asks bound hosts for uncompressed responses (`Accept-Encoding: identity`) and replaces every real value in their response headers and body with a same-length `HUSH_REDACTED***` marker. That only catches the value as it was sent. A server that compresses anyway, escapes or re-encodes the key (base64, JSON `\u` escapes), echoes part of it, or splits it across chunk boundaries or responses still leaks it. Only bind hosts you trust with the key.

**A key that gets another key.** hush keeps the child from reading the key, not from using it: every request the child sends to the bound host carries the real value, so the child can do anything the key allows there. With many vendor APIs that includes creating a new API key, exchanging the key for an OAuth or session token, or reading back a stored credential. The new credential comes back in an ordinary response, and the redaction above only knows the values in the vault, so the child gets it in full and can send it anywhere. Where the vendor offers one, bind a restricted key: limited to the endpoints the work needs, unable to create or manage keys, and with a spending or rate limit if there is one.

**Automation escape hatches** (`HUSH_PASSPHRASE`, `HUSH_SECRET_VALUE` env vars, used instead of the interactive hidden prompt) exist for scripting/testing. They're less safe than the interactive prompt — the value becomes visible in the process environment — so avoid them for anything beyond local automation you control.

## Building

```bash
cargo build --release
cargo install --path .      # puts hush in ~/.cargo/bin
hush --version              # hush 0.1.3 (93db286 2026-10-10)
```

`--version` shows the version and the commit the binary was built from, with `-dirty` after the hash if the tree had uncommitted changes. Every merge to master that changes the program gets its own patch version, a `v<version>` tag and an entry in [CHANGELOG.md](CHANGELOG.md), all added by CI once the tests pass.

No system dependencies beyond a Rust toolchain; all cryptography (`age`) and HTTP parsing are pure-Rust crates, so there's no equivalent of the "no prebuilt wheel for this platform" problem that motivated keeping this simple in the first place.

## License

Copyright 2026 Matteo Marras. Licensed under the
[Apache License, Version 2.0](LICENSE).
