# hush

[![CI](https://github.com/matteo1994/hush/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/matteo1994/hush/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](https://github.com/matteo1994/hush/blob/master/LICENSE)
![Platforms](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey)

A local, placeholder-swap credential proxy that keeps real API keys out of an AI coding agent's own context, memory, and transcript. The crate is `hush-secrets`; the program it installs is `hush`.

This page is the short version. The [full README](https://github.com/matteo1994/hush#readme) on GitHub covers the design, every command and the threat model.

## How it works

`hush run -- CMD` decrypts only the secrets the project names, starts a loopback proxy and runs `CMD` with a random placeholder in place of each real value, so `CMD`'s environment never holds the real bytes. When `CMD` sends a request through the proxy, hush swaps the placeholder for the real value on the wire, but only if the request is going to the host that secret is bound to. A request anywhere else gets the placeholder, verbatim. A prompt-injected agent told to send "the API key" to an attacker has nothing to send.

Secrets live in a vault encrypted with a passphrase (age), and every change to a secret, or to where it may be sent, needs that passphrase, which nothing inside `hush run` ever gets.

**Scope:** static HTTP(S) header credentials only, such as `Authorization: Bearer …` or an API-key header. Not database credentials, SSH keys, or signed requests like AWS SigV4. See [Scope](https://github.com/matteo1994/hush#scope-https-header-based-api-keys-only) and [Current scope](https://github.com/matteo1994/hush#current-scope-v0) for what clients work.

## Install

Rust 1.89 or newer, and a C compiler (`ring` builds some C). Install hush where only an administrator can write, not in `~/.cargo/bin`, where a process running as you could replace it with one that keeps your passphrase:

```bash
build=$(mktemp -d)
cargo install --locked hush-secrets --root "$build"
sudo install -d -m 755 /opt/hush/bin
sudo install -m 755 "$build/bin/hush" /opt/hush/bin/
rm -rf "$build"
```

Then put `/opt/hush/bin` first on your `PATH`. On macOS, also sign it with the hardened runtime after each install, which refuses debugger reads and injected libraries:

```bash
sudo codesign -f -s - -o runtime /opt/hush/bin/hush
```

Why both matter: [Installing](https://github.com/matteo1994/hush#installing).

## Quick start

```bash
hush init                                              # create the vault, set its passphrase
hush secret add BILLING_API_KEY --host api.example.com # prompts for the value, hidden
hush secret ls                                         # names and bindings, never values
hush run -- python billing_client.py                   # the names in .env get placeholders
hush run --secret OPENAI_API_KEY -- claude             # an agent and everything it starts
```

## More in the README

- [Which secrets a command gets](https://github.com/matteo1994/hush#which-secrets-get-exposed-to-a-given-command) and [profiles](https://github.com/matteo1994/hush#profiles-the-same-name-a-different-key-per-project): a different key under the same name per project
- [Rotating a key](https://github.com/matteo1994/hush#rotating-a-key)
- [Agent apps on macOS](https://github.com/matteo1994/hush#without-a-terminal-agent-apps-on-macos): MCP servers in the Claude desktop app, unlocked with Touch ID
- [Threat model](https://github.com/matteo1994/hush#threat-model): what hush protects against, and what it can't
- [Reporting a vulnerability](https://github.com/matteo1994/hush/blob/master/SECURITY.md) · [Changelog](https://github.com/matteo1994/hush/blob/master/CHANGELOG.md)
