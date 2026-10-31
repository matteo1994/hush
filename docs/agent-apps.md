# How agent apps reach their model API

A survey for the `agent-apps` route: for each app people use to run an AI agent, which process sends the request to the model API, where the key comes from, and whether that request can go through `hush run`. hush can only help where three things hold:

1. **The key comes from the environment**, or from somewhere a placeholder can go. A key the app keeps in the OS keychain or its own secret storage is the real key, so hush has nothing to swap until placeholders are stable across runs (see the *stable placeholders* step).
2. **The process sending the request inherits `hush run`'s environment** and honors `HTTPS_PROXY` plus one of hush's CA variables (`SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, …). A client that ignores them fails with a TLS error against a bound host. It does not leak.
3. **The request goes to the provider**, not through the app vendor's servers. A key sent to the vendor's backend reaches a host it isn't bound to, so it keeps its placeholder, and binding it to the vendor's host would hand the real key to the vendor.

Apps that sign in with an account (GitHub Copilot, Claude desktop's chat, Cursor's own models, JetBrains AI's subscription) have no key at all, so they are out of scope.

**Verified** means tested against postman-echo with a placeholder key and checked that the real value went out and was redacted in the echo. Everything else is what vendor docs or user reports say, as of 2026-10-31, and is marked with its source.

## Summary

| App / extension | Who sends the request | Key from | Through hush? |
|---|---|---|---|
| VS Code extension host (Node `https`, `fetch`) | extension host (Node 24, VS Code 1.125.1) | whatever the extension reads | **Verified**, with `http.fetchAdditionalSupport: false` for `fetch` |
| VS Code: a process an extension spawns (bundled CLI, MCP server, `curl`) | that child process | its env | **Verified** (Node child and `curl`) |
| VS Code integrated terminal | the shell's commands | env | **Verified**: placeholders, proxy and `HUSH_ACTIVE` are set |
| Claude Code for VS Code | the bundled `claude` CLI it spawns | `ANTHROPIC_API_KEY` in env, or a claude.ai login | Should work: same path as a spawned child above, and `hush run -- claude` is hush's main use. Not tested with the extension itself |
| OpenAI Codex for VS Code | the bundled Codex CLI | `OPENAI_API_KEY` in env ([OpenAI docs][codex-key]), or a ChatGPT login | Unverified: the key path fits; whether the CLI trusts `SSL_CERT_FILE` is unknown |
| Cline, Roo Code | extension host | VS Code secret storage (the keychain) ([analysis][cline-secrets]) | Not yet: the key isn't in env. Needs stable placeholders |
| Continue | extension host | `config.yaml`, `${{ secrets.NAME }}`; has its own `requestOptions.proxy` / `caBundlePath` ([docs][continue]) | Not yet, same reason; its own CA setting would also need the run's CA path |
| GitHub Copilot | extension host | GitHub sign-in | Out of scope. Its BYOK models ([changelog][copilot-byok]) keep the key in secret storage: same as Cline |
| Claude desktop: MCP servers | the server process | its env, via `hush run` in `claude_desktop_config.json` | **Verified** (see README, *Without a terminal*) |
| Claude desktop: chat | the app | claude.ai sign-in | Out of scope |
| Cursor | Cursor's servers, even with your own key ([Cursor help][cursor-byok]) | Cursor settings | No: the key goes to Cursor's backend, not the provider |
| Windsurf | reportedly the provider directly for BYOK models ([third-party][windsurf]) | Windsurf settings | Unverified, and the key is in settings, not env |
| Zed | the Zed process (Rust) | `ANTHROPIC_API_KEY` etc. in env, which wins over the keychain ([Zed docs][zed-keys]) | Promising: the key path fits, and Zed reads `HTTPS_PROXY` ([Zed docs][zed-proxy]). Whether it trusts `SSL_CERT_FILE` is unknown; if not it fails closed |
| JetBrains AI Assistant BYOK | the IDE (JVM) | IDE settings, stored locally ([JetBrains][jetbrains]) | Unlikely: the key isn't in env, and the JVM uses its own proxy settings and trust store |

## VS Code in detail

Tested on macOS with VS Code 1.125.1 (Node 24.15.0 in the extension host). A probe extension made the same request four ways, with a `TEST_KEY` placeholder bound to `postman-echo.com`: Node `https`, `fetch`, a spawned `curl`, and a spawned Node child. It also read the integrated terminal's environment. That probe is `scripts/vscode-check/`; `run.sh` repeats the check on any VS Code.

**The extension host inherits `hush run`'s environment** when VS Code is started by `hush run`: the placeholders, `HTTPS_PROXY`, `NODE_EXTRA_CA_CERTS`, `NODE_USE_ENV_PROXY`, `HUSH_ACTIVE`. So do the processes it spawns and the integrated terminal.

**Node `https` in an extension works as is.** VS Code's proxy agent (`http.proxySupport: override`) reads `HTTPS_PROXY`, and the request was swapped and the echo redacted.

**`fetch` in an extension fails by default** with `self signed certificate in certificate chain`. VS Code patches the extension host's `fetch` (`http.fetchAdditionalSupport`, on by default) and that path does not trust `NODE_EXTRA_CA_CERTS`. Nothing leaks, but most model SDKs use `fetch`. Either of these settings fixes it:

| Setting | Effect |
|---|---|
| `"http.fetchAdditionalSupport": false` | `fetch` falls back to Node's own, which honors `NODE_USE_ENV_PROXY` and `NODE_EXTRA_CA_CERTS`. Only touches `fetch`, so it's the one to use |
| `"http.systemCertificates": false` | also works, but drops the OS keychain's certificates for every request from extensions |
| `"http.experimental.systemCertificatesV2": true` | does not help |

**How VS Code is started matters, because `hush run` ends when its command does:**

| Start with | Result |
|---|---|
| `…/Visual Studio Code.app/Contents/MacOS/Code --user-data-dir DIR` | **Works.** The run lasts until VS Code quits |
| `code --wait --new-window --user-data-dir DIR` | Works. `--wait` returns when that window closes, though, so with more windows open the run would end under them (not tested) |
| `code` without `--wait` | `code` returns in about 2s, the run and its proxy end, and keyed requests from VS Code then hang. Fails closed |
| any of these while VS Code already runs with that user-data dir | VS Code is single-instance per user-data dir, so the launch is handed to the running instance. Plain `code --wait` hangs on a handoff with no file to wait for. Not supported |

A separate `--user-data-dir` gives a VS Code instance of its own, so it can run beside an ordinary VS Code. It has its own settings and sign-ins; extensions still come from `~/.vscode/extensions` unless `--extensions-dir` says otherwise. The README's *VS Code* section has the recipe.

Two side effects:

- **`HUSH_ACTIVE` is set in the integrated terminal**, so `hush run` there refuses to start. Commands in it already get the placeholders and the proxy, so `claude` there needs no `hush run`.
- **The placeholders change every run.** That's fine for anything that reads its key from the environment. A key pasted into an extension's settings (Cline, Continue, Copilot BYOK) is the real key, which hush neither sees nor swaps.

## What this means for the route

- **VS Code with env-reading extensions works today** (Claude Code, likely Codex, anything an extension spawns), from a terminal, with a dedicated user-data dir and one setting. Launching it from the Dock is the *launcher* step.
- **Extensions that keep the key in secret storage** (Cline, Roo, Continue, Copilot BYOK) are the larger group. They need the *stable placeholders* step: a placeholder pasted into the extension's key field once, that stays valid across runs.
- **Zed** is the most promising non-VS Code app: it reads the key from env and the proxy from `HTTPS_PROXY`. The open question is its CA trust.
- **Cursor** can't be helped: its own-key requests go through Cursor's servers.
- **Chromium networking** (the *trust* step) matters less than expected for VS Code: extensions make their requests from Node, not the renderer.

[codex-key]: https://developers.openai.com/codex/guides/api-key
[cline-secrets]: https://agent-safehouse.dev/docs/agent-investigations/cline
[continue]: https://docs.continue.dev/reference
[copilot-byok]: https://github.blog/changelog/2026-04-22-bring-your-own-language-model-key-in-vs-code-now-available/
[cursor-byok]: https://cursor.com/help/models-and-usage/api-keys
[windsurf]: https://kitemetric.com/blogs/unlocking-anthropic-s-opus-sonnet-4-in-windsurf-a-byok-guide
[zed-keys]: https://zed.dev/docs/ai/use-api-access
[zed-proxy]: https://github.com/zed-industries/zed/issues/9422
[jetbrains]: https://www.jetbrains.com/help/ai-assistant/bring-your-own-key-byok.html
