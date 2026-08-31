# SelfHostAuth — Self-Hosted TOTP Authenticator & 2FA Sync Server

> **Open source, self-hosted alternative to Google Authenticator, Authy, 2FAS & Aegis.** Privacy-focused TOTP / HOTP authenticator with encrypted sync across **Windows, macOS, Linux, iOS, Android & browser** — you own the server, you own the data.

[![CI](https://github.com/wildfirebill-security/selfhostauth/actions/workflows/ci.yml/badge.svg)](https://github.com/wildfirebill-security/selfhostauth/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/wildfirebill-security/selfhostauth?label=release)](https://github.com/wildfirebill-security/selfhostauth/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux%20%7C%20iOS%20%7C%20Android%20%7C%20Chrome%20%7C%20Firefox-lightgrey)](https://github.com/wildfirebill-security/selfhostauth/releases)
[![Self-Hosted](https://img.shields.io/badge/self--hosted-%E2%9C%93-success)](docker/docker-compose.yml)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-blue?logo=typescript)](https://www.typescriptlang.org/)

**SelfHostAuth is a self-hosted 2FA authenticator** that syncs your TOTP & HOTP one-time codes across every device without trusting Google, Authy, or any third-party cloud. Run the lightweight **Node.js + SQLite sync server** on your home server, NAS, Raspberry Pi, or VPS, and access your 2FA codes from a native **desktop app (Electron)**, **mobile app (iOS/Android via bare React Native — 100% OSS, no Expo)**, and **browser extension (Chrome/Edge/Firefox MV3)** — all offline-capable and end-to-end encrypted at rest.

*Keywords: self-hosted authenticator, self-hosted 2FA, open source 2FA, TOTP server, HOTP, OTP authenticator, 2FA sync, privacy authenticator, Google Authenticator alternative, Authy alternative*

---

## Why SelfHostAuth? Self-Hosted 2FA vs Cloud Authenticators

| Feature | SelfHostAuth (self-hosted) | Google Authenticator | Authy (Twilio) | 2FAS / Aegis |
|---|---|---|---|---|
| **Own your data** | ✅ Your server, your SQLite DB | ❌ Google cloud | ❌ Twilio cloud | ⚠️ Device / encrypted backup |
| **Cross-device sync** | ✅ Encrypted, revision-based | ✅ (since 2023) | ✅ | ⚠️ Manual export |
| **Open source** | ✅ MIT, fully auditable | ❌ | ❌ | ✅ |
| **Offline codes** | ✅ Cached + local TOTP | ✅ | ✅ | ✅ |
| **Desktop (Win/Mac/Linux)** | ✅ Electron (NSIS/DMG/AppImage, deb, rpm) | ❌ | ❌ (discontinued) | ❌ |
| **Browser extension** | ✅ MV3 (Chrome/Edge/Firefox) | ❌ | ❌ | ❌ |
| **Self-host anywhere** | ✅ Docker, bare metal, Raspberry Pi, NAS | — | — | — |

**Perfect for:** homelabbers, privacy advocates, teams that need a **self-hosted OTP / 2FA server**, and anyone searching for a **Google Authenticator self-hosted alternative** or **Authy replacement**.

---

## Features — Self-Hosted Authenticator with Everything You Need

- **RFC-compliant TOTP / HOTP** — RFC 4226 / RFC 6238, SHA-1 / SHA-256 / SHA-512, 6–8 digits, any period
- **Import via QR / otpauth://** — scan or paste a QR-code URI or raw base32 secret
- **AES-256-GCM vault encryption at rest** — every secret encrypted on your server; key in a file you control (`ENCRYPTION_KEY`)
- **Secure auth** — `scrypt` passwords, SHA-256 hashed tokens, sliding sessions, rate limiting, **optional TOTP 2FA on the account itself**
- **Revision-based sync** — push/pull with last-write-wins + tombstones, so delete on one device deletes everywhere
- **Offline-first** — clients cache the vault locally and compute TOTP without the server (pure-JS HMAC fallback for React Native)
- **Zero native deps on the server** — Node 22+ built-in `node:sqlite` + `node:crypto`; <50 MB Docker image
- **Runs anywhere** — Docker Compose, systemd, bare metal on **Windows, macOS, and 8+ Linux distros** (Ubuntu, Debian, Fedora, Arch, etc. via AppImage/deb/rpm)

```
┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌─────────────┐
│  Desktop   │  │  Mobile    │  │  Extension │  │  Mobile    │  │  Desktop    │
│ (Electron) │  │ (iOS/Android)│ │  Chrome/FF │  │ (iOS)      │  │ (macOS/Linux)│
└─────┬──────┘  └─────┬──────┘  └─────┬──────┘  └─────┬──────┘  └─────┬──────┘
      │               │               │               │               │
      └───────────────┴───────────────┴───────────────┴───────────────┘
                              ▲ HTTPS (Caddy / reverse proxy)
                              │
                    ┌─────────┴──────────┐
                    │  Your 2FA Server   │
                    │  Node + SQLite     │
                    │  AES-256-GCM at rest│
                    │  scrypt passwords  │
                    └────────────────────┘
```

---

## Repo Layout

| Path | What it is |
|------|------------|
| `packages/core` | **TOTP/HOTP engine**, otpauth parsing, AES-GCM crypto, types — zero deps, runs everywhere |
| `packages/client` | Typed TypeScript API client for the sync server |
| `apps/server` | **Self-hosted 2FA sync server** (Fastify + SQLite) — the brain |
| `apps/desktop` | **Desktop authenticator** — Electron for Windows / macOS / Linux |
| `apps/extension` | **Browser extension** — Chrome / Edge / Firefox (Manifest V3) |
| `apps/mobile` | **Mobile 2FA app** — bare React Native 0.76 for iOS & Android (fully OSS) |
| `docker` | `Dockerfile`, `docker-compose.yml`, `Caddyfile`, `systemd` unit |

---

## Quick Start — Run Your Own 2FA Server in 2 Minutes

**Prereqs:** Node.js ≥ 22 and pnpm ≥ 9 (`corepack enable`).

```bash
# 1. Install, build, and test (validates RFC 4226/6238 vectors)
pnpm install
pnpm build
pnpm test

# 2. Start the self-hosted server
cd apps/server
pnpm start        # http://0.0.0.0:8787  •  data in ./data
```

Verify your **self-hosted TOTP server** is up:

```bash
curl http://127.0.0.1:8787/api/v1/info
# {"name":"selfhostauth","version":"0.1.6","features":{"sync":true,...}}
```

---

## Install the Apps — One Authenticator on Every Device

### Windows / macOS / Linux Desktop (Electron)

```bash
pnpm dev:desktop        # dev with HMR
pnpm build:desktop      # production build
cd apps/desktop
pnpm package:win        # → NSIS .exe (Windows)
pnpm package:mac        # → DMG (macOS, run on Mac)
pnpm package:linux      # → AppImage + .deb + .rpm (run on Linux)
# Or download prebuilt installers from Releases
```

Open the app → point it at your server URL → **Register** → start adding your 2FA codes.

### Chrome / Edge / Firefox Extension (MV3)

```bash
cd apps/extension
pnpm build              # → dist/
# pnpm package → selfhostauth-extension.zip
```

- **Chrome / Edge:** `chrome://extensions` → Developer mode → **Load unpacked** → `apps/extension/dist`
- **Firefox:** `about:debugging` → This Firefox → Load Temporary Add-on → `manifest.json`
- Click the toolbar icon → ⚙ → enter your server URL + credentials.

> Requests host permission for your server origin on first connect (MV3 security model).

### iOS / Android Mobile App (Bare React Native — 100% OSS)

No Expo, no vendor lock-in — pure **React Native 0.76** + `@react-native-clipboard/clipboard`. Requires Xcode (iOS) or Android Studio + JDK 17.

```bash
cd apps/mobile
pnpm install

# iOS — install pods, then run on simulator/device
cd ios && pod install && cd ..
pnpm run ios            # or: npx react-native run-ios

# Android — builds an APK with Gradle
pnpm run android        # or: npx react-native run-android

# Or build release artifacts directly
cd android && ./gradlew assembleRelease   # → app/build/outputs/apk/release/
cd ios && xcodebuild -workspace selfhostauth.xcworkspace -scheme selfhostauth -configuration Release -sdk iphonesimulator -derivedDataPath ../build CODE_SIGNING_ALLOWED=NO build
```

Native projects (`android/` / `ios/`) are committed (no Expo prebuild). CI builds both on every `workflow_dispatch` via `.github/workflows/mobile-local.yml`. TOTP works **offline** via the pure-JS HMAC fallback in `packages/core`.

---

## Self-Hosting — Docker (Recommended) or Bare Metal

### Option A — Docker Compose (any Linux, NAS, Raspberry Pi, VPS)

```bash
cd docker
# Generate a stable vault key (keep it safe — lose it and the vault is unrecoverable)
export ENCRYPTION_KEY=$(node -e "console.log(require('crypto').randomBytes(32).toString('base64'))")
docker compose up -d
```

Your **self-hosted 2FA server** is now at `http://localhost:8787`. Put it behind **Caddy** (see `docker/Caddyfile`) or any reverse proxy for HTTPS — **required for mobile apps and browser extensions on non-localhost**.

### Option B — Bare Metal (Windows, macOS, any Linux distro)

```bash
cd apps/server
npm i -g pnpm && pnpm install && pnpm build
ENCRYPTION_KEY=<32-byte-base64> DATA_DIR=/var/lib/selfhostauth PORT=8787 pnpm start
```

A `systemd` unit is included at `docker/selfhostauth.service`:

```bash
sudo cp docker/selfhostauth.service /etc/systemd/system/
sudo systemctl enable --now selfhostauth
```

---

## Configuration — Environment Variables for Your 2FA Server

| Variable | Default | Purpose |
|----------|---------|---------|
| `PORT` | `8787` | HTTP port |
| `HOST` | `0.0.0.0` | Bind address |
| `DATA_DIR` | `./data` | SQLite DB + auto-generated `encryption.key` |
| `ENCRYPTION_KEY` | auto-generated | **32-byte base64 AES key** — set it for multi-instance / backup stability |
| `ALLOW_REGISTRATION` | `true` | Set `false` to disable open signup (private server) |
| `SESSION_TTL_DAYS` | `30` | Session lifetime (sliding) |
| `RATE_LIMIT_PER_MINUTE` | `20` | Per-IP auth rate limit |

---

## Security Model — How Your 2FA Secrets Stay Safe

- **Passwords:** `scrypt` (N=16384, r=8, p=1) with per-user salt — resistant to GPU cracking.
- **Vault at rest:** **AES-256-GCM** per item; key is the server's `encryption.key` (file or `ENCRYPTION_KEY` env). Stealing the DB without the key is useless.
- **Sessions:** 64-char random tokens, stored only as SHA-256 hashes, sliding expiry.
- **Account 2FA:** optional TOTP required at login when enabled.
- **In transit:** TLS via your reverse proxy; no unauthenticated API.
- **Local computation:** clients compute TOTP locally — the server is never asked for codes during normal use (`/verify` exists only for testing/CI).

> **Roadmap:** client-side E2E encryption (master password), WebAuthn passkeys, family sharing, additional OTP types, push notifications. PRs welcome.

---

## Development — Build, Test, Contribute

```bash
pnpm build             # build all packages/apps (topological order)
pnpm typecheck         # desktop + mobile + extension
pnpm test              # core RFC vectors (12) + server API (9) = 21 tests
pnpm dev:server        # server watch mode
pnpm dev:desktop       # Electron + Vite HMR
pnpm dev:extension     # rebuild extension on change
pnpm --filter @selfhostauth/mobile start  # bare React Native Metro
```

The core library is validated against **official RFC 4226 (HOTP), RFC 6238 (TOTP) and RFC 4231 (HMAC) test vectors** for SHA-1, SHA-256 and SHA-512, including the **pure-JS fallback path used on React Native** (no WebCrypto).

### CI/CD

Every push runs on **Ubuntu / Windows / macOS × Node 22 & 24**: build → typecheck → test → live smoke test. Tags `v*` publish:
- **Desktop installers** to the GitHub Release (Win NSIS, macOS DMG, Linux AppImage/deb/rpm)
- **Server Docker image** to `ghcr.io/wildfirebill-security/selfhostauth`
- **Extension zip** + **mobile APK / iOS simulator build** via bare React Native (Gradle / Xcode) — no Expo required

See `.github/workflows/` for details.

---

## FAQ — Self-Hosted Authenticator

**Is this a Google Authenticator alternative I can self-host?**
Yes — SelfHostAuth is a drop-in, **open source alternative to Google Authenticator and Authy** that you host yourself for full privacy and no vendor lock-in. Import your existing `otpauth://` URIs in one paste.

**Can I self-host my 2FA codes? Is it safe?**
Yes. Your TOTP secrets never leave your infrastructure unencrypted. They are AES-256-GCM encrypted at rest and your server is the only copy unless you enable backups. Use HTTPS + a strong `ENCRYPTION_KEY`.

**What platforms are supported?**
**Server:** Windows, macOS, and 8+ Linux distros (anywhere Node 22+ runs, via Docker or bare metal). **Clients:** Windows, macOS, Linux desktop; iOS & Android mobile; Chrome, Edge, Firefox extension.

**Does it work offline?**
Yes. All clients cache the vault and compute TOTP offline. You only need the server to add/sync/delete codes across devices.

**How do I migrate from Google Authenticator / Authy / 2FAS / Aegis?**
Export your codes as `otpauth://` URIs (Google Authenticator: Transfer → Export; Aegis: Export → plain JSON; 2FAS: backup file). In any SelfHostAuth client: **Add → paste the URI** → sync.

**What about Authy shutting down its desktop app?**
SelfHostAuth is an ideal **Authy replacement** with a real desktop app plus browser and mobile clients — and you won't lose access if a vendor sunsets a product again.

**Is there a hosted version?**
No. SelfHostAuth is **self-hosted only** by design. If you want zero ops, run the one-command Docker Compose on a $5 VPS or Raspberry Pi.

---

## License

MIT — see [LICENSE](LICENSE).

---

<p align="center"><sub>Keywords for discoverability: self-hosted authenticator, self-hosted 2FA, open source authenticator, TOTP authenticator, HOTP, OTP manager, 2FA sync server, private 2FA, Google Authenticator alternative, Authy alternative, 2FAS alternative, Aegis alternative, self-hosted OTP, self-hosted 2FA server, privacy 2FA, homelab 2FA</sub></p>
