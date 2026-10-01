# Release 2 repository security audit

Audit date: 2026-10-02. Repository was freshly cloned from the owner's existing GitHub origin; original branch `main`, clean tree, no existing tags/releases. No production hosts, SSH credentials or running tunnels were accessed.

## Scope and results

- Reviewed all tracked files and all **three original commits / 63 unique historical blobs** from every reachable Git ref. `git fsck --full --no-reflogs` found no additional dangling material. Full current-tree scan was repeated after implementation/staging.
- Searched for WireGuard private keys/PSKs, udp2raw keys, Shadowsocks/server passwords, SSH private keys, API keys/tokens/cookies/credentials, production configuration, environments, backups, temporary files, logs and packet captures.
- Examined credential-like assignments and flags with values redacted in terminal output. Historical key/secret fields were placeholders. No literal private keys, passwords, carrier secrets, tokens, backup/log/packet-capture payloads or credential-bearing configuration were found.
- **Gitleaks 8.30.1**, official Linux binary checksum verified, scanned the full Git history with redaction and the current directory: **no leaks found**. Scans do not prove absence of every possible credential form; manual review supplements pattern detection.
- Historical public production IPs, fixed private addressing and interface names existed in configuration/documentation. They are **administrative topology references**, not exposed cryptographic secrets. Release 2's current tree removes those production references and runtime assumptions. Historical commits retain provenance; they are not installable Release 2 configurations.
- Generated credentials, pairing JSON, runtime configuration, backups, logs, diagnostics, `.env` files, captures and temporary files are ignored. The tracked example contains public defaults/documentation IPv4 only. Tests generate dummy or transient real key material locally, never commit it.

## History disposition

A full private Git bundle was preserved outside the repository with mode 0600 before refactoring. No credential exposure requiring rotation/history rewriting was identified, so **no history rewrite or force-push was performed**. Public topology history is retained. The backup is not uploaded or committed.

If later evidence identifies an actual exposed production credential, it must be rotated and removed from history with a preserved private backup; deletion in a later commit is insufficient. This audit is about repository content and installer handling, not a live host penetration test or a complete audit of upstream udp2raw/WireGuard.

## Current-tree checks

PASS: no tracked secrets; production-specific runtime values removed; strict data parsing; protected secret files; independent keys; protected pairing transfer; no secrets in units/argv; sanitized diagnostics; scoped firewall/uninstall; bounded recovery. See [validation](validation.md) for tested scope and limitations.
