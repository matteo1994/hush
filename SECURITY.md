# Security policy

## Reporting a vulnerability

Please report it privately, through GitHub: on this repository's **Security** tab, choose **Report a vulnerability**. That opens a private advisory that only you and the maintainer can see. Don't open a public issue or pull request for it.

Say what an attacker can do, and how: the commands or requests that show it, the hush version (`hush --version`) and the operating system. I aim to reply within a week. Once a fix is released, the advisory is published, crediting you unless you'd rather not be named.

## Supported versions

Only the latest release gets fixes. hush has no release branches, so a fix ships as the next patch version; update to it.

## What counts

hush's job is set out in the [threat model](README.md#threat-model). A vulnerability is a way around it, for example:

- a real secret value reaching a `hush run` child: its environment, its arguments, its output, or any response it reads;
- a real value sent anywhere but its bound host, or over plain HTTP where the binding doesn't allow it;
- the proxy decrypting a connection to a host no minted secret is bound to;
- hush accepting a vault it didn't write with the passphrase, or a change to a secret or to where it may go that the passphrase didn't approve (other than an older copy of the vault, below);
- the run's CA private key reaching disk;
- the proxy and an upstream server disagreeing about where a request ends (request smuggling);
- a server's response that crashes the proxy. A child can always stop hush itself, since it runs as you, so a crash it causes only counts if it gets a real value out.

These are among the known limits the threat model describes, and aren't vulnerabilities on their own:

- anything that needs root, or, on macOS, a process allowed to read another's memory (Developer Mode or `DevToolsSecurity -enable`) when hush isn't signed with the hardened runtime;
- a same-user process tricking you into typing the passphrase somewhere it can read it, or replacing a `hush` binary you installed where your user can write;
- restoring an older copy of the vault file, or deleting or locking the files in `~/.config/hush`;
- a bound host that echoes only part of the key; splits one value across two responses, between chunk data and a trailer, or across the blank line between headers and body; sends a compressed body without declaring a content encoding, or behind a response head hush cannot parse; or re-encodes the key in a form hush does not scan (a second layer of encoding, HTML entities, base64 broken up with whitespace, base64 of a secret shorter than 4 bytes, or base64 preceded by another base64-alphabet character, including a run that mixes `+/` with `-_`);
- what the key itself allows at its bound host, such as creating another key;
- profiles not separating projects from each other: one vault and one passphrase hold them all;
- `HUSH_PASSPHRASE` and `HUSH_SECRET_VALUE` being visible to whatever can read the environment they're set in;
- credentials hush doesn't handle: anything but a static HTTP header, such as database passwords, SSH keys or signed requests.

If you're not sure whether something counts, report it anyway.
