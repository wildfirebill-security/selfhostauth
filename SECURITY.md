# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| `main` (latest) | ✅ |
| Latest tagged `v*` | ✅ |
| Older tags | ❌ (please upgrade) |

We publish patched Docker images to `ghcr.io/wildfirebill-security/selfhostauth` and
installers to [Releases](https://github.com/wildfirebill-security/selfhostauth/releases).

## Reporting a vulnerability

**Do not open a public issue.**

Use one of these private channels:

1. **GitHub — Private vulnerability reporting** (preferred):
   `Security → Report a vulnerability` on this repo. You can request a CVE and
   track the fix in a private fork.

2. **Email:** `security@wildfirebill-security` (if configured) — encrypt with the
   maintainer's PGP key if you have it.

Include: affected version/commit, steps to reproduce, impact, and any PoC.
We aim to acknowledge within **3 business days** and to ship a fix or mitigation
within **30 days** for high-severity issues.

## What to expect

- We will confirm receipt and keep you updated.
- If confirmed, we will create a private fix branch, request a CVE if warranted,
  and credit you in the advisory unless you prefer to remain anonymous.
- Once a fix is released, we will publish a GitHub Security Advisory and
  recommend upgrading. Please `docker pull` / reinstall promptly.

## Hardening your deployment

- Always set a stable `ENCRYPTION_KEY` (32-byte base64) — losing it makes the vault unrecoverable; leaking it exposes secrets at rest.
- Put the server behind **HTTPS** (Caddy example in `docker/Caddyfile`) — required for mobile and browser extension on non-localhost.
- Set `ALLOW_REGISTRATION=false` for private instances and create users out-of-band.
- Keep Node ≥ 22 and `pnpm` up to date; run `pnpm audit` in CI.

## Scope

This policy covers the code in this repository (`apps/server` auth/crypto/sync,
`apps/web`/`desktop`/`mobile`/`extension`, and `packages/core`). It does not cover
third-party dependencies beyond how we use them — but we do track `pnpm audit`
and Dependabot.

*Thanks for helping keep SelfHostAuth and its users safe.*
