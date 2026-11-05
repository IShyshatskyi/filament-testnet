# Security policy

## Supported versions

| Component | Supported |
|-----------|-----------|
| Filament (this repository) | `main`, the latest synced version (see `VERSION`) |

This is experimental testnet software. See [DISCLAIMER.md](DISCLAIMER.md).

## Reporting a vulnerability

**Do not** open a public issue for a security bug.

Email **hcrncontact@gmail.com** with `[security]` in the subject and:

1. A description and the impact (a proof accepted that should not be, a funds or key issue, remote code execution, a denial of service).
2. The affected version (`VERSION` file or commit) and network.
3. Steps to reproduce, or a proof of concept.
4. Your PGP key if you want an encrypted reply.

We aim to acknowledge within **72 hours** and to give a status update within **7 days**.

## Scope

**In scope:** proof and header verification (`filament-types`), the handshake and wire codec
(`filament-p2p`), the client and its local HTTP API (`filament`), the wallet and invoice code, and
the sync and boundary scripts.

**Out of scope:** third-party pools and nodes, social engineering, physical attacks, denial of service
without a verification impact. Findings in the node software (Keystone, Kameniar) belong to the same
address but are handled in the node repository.

## Coordinated disclosure

* 90-day default disclosure window after a fix is available.
* Credit in the release notes unless you ask to stay anonymous.
* Before mainnet there is no monetary bounty.

For what the client does and does not guarantee, read [docs/security.md](docs/security.md) first:
some behaviour that looks like a flaw is a stated limit.
