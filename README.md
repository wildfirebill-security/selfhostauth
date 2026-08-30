# selfhostauth

A self-hosted, multi-platform authenticator (TOTP) with encrypted cloud sync.

Your one-time codes, synced across **Windows, macOS, Linux, iOS, Android** and your
**browser** — without trusting a third-party cloud. You run the server, so you own
the data.

```
┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌─────────────┐
│  Desktop   │  │  Mobile    │  │  Extension │  │  Mobile    │  │  Desktop    │
│ (Electron) │  │ (iOS/Android)│ │  Chrome/FF │  │ (iOS)      │  │ (macOS/Linux)│
└─────┬──────┘  └─────┬──────┘  └─────┬──────┘  └─────┬──────┘  └─────┬──────┘
      │               │               │               │               │
      └───────────────┴───────────────┴───────────────┴───────────────┘
                              ▲ HTTPS
                              │
                    ┌─────────┴──────────┐
                    │  Your server       │
                    │  Node + SQLite     │
                    │  AES-256-GCM at rest│
                    │  scrypt passwords  │
                    │  optional 2FA      │
                    └────────────────────┘
```

## Features

- **TOTP / HOTP** engine — RFC 4226 / RFC 6238, SHA-1/256/512, 6–8 digits, any period
- **otpauth:// import** — paste a QR-code URI or a raw base32 secret
- **Encrypted sync** — every secret is AES-256-GCM encrypted at rest on your server;
  the key lives in a file you control (or `ENCRYPTION_KEY`)
- **Revision-based sync** — push/pull merge with last-write-wins + tombstones, so
  deleting on one device deletes everywhere
- **Account 2FA** — optional TOTP on the server account itself
- **Offline-friendly** — clients cache codes locally and compute TOTP without the
  server
- **Zero native deps on the server** — Node 22+ built-in SQLite (`node:sqlite`),
  scrypt from `node:crypto`

## Repo layout

| Path | What |
|------|------|
| `packages/core` | TOTP, otpauth parsing, crypto, types — zero-dependency, runs on every platform |
| `packages/client` | Typed API client for the server |
| `apps/server` | Self-hosted sync server (Fastify + SQLite) |
| `apps/desktop` | Electron app — **Windows / macOS / Linux** (NSIS / DMG / AppImage, deb, rpm) |
| `apps/extension` | Browser extension — **Chrome / Edge / Firefox** (Manifest V3) |
| `apps/mobile` | Expo (React Native) app — **iOS / Android** |
| `docker` | Dockerfile, docker-compose, Caddyfile, systemd unit |

## Quick start

Prereqs: **Node.js ≥ 22**, **pnpm ≥ 9** (Corepack: `corepack enable`).

```bash
# 1. install + build + test
pnpm install
pnpm build
pnpm test

# 2. run the server
cd apps/server
pnpm start        # listens on http://0.0.0.0:8787, data in ./data
```

Verify:

```bash
curl http://127.0.0.1:8787/api/v1/info
# {"name":"selfhostauth","version":"0.1.0","features":{...}}
```

## Run the desktop app

```bash
pnpm dev:desktop        # dev mode with HMR
pnpm build:desktop      # production build
cd apps/desktop
pnpm package:win        # Windows NSIS installer
pnpm package:mac        # macOS DMG   (run on macOS)
pnpm package:linux      # AppImage + deb + rpm  (run on Linux)
```

Point it at your server, register, and start adding codes.

## Install the browser extension

```bash
cd apps/extension
pnpm build              # builds dist/ (or `pnpm package` for a .zip)
```

1. Chrome/Edge: open `chrome://extensions` → Developer mode → **Load unpacked** →
   select `apps/extension/dist`.
2. Firefox: about:debugging → This Firefox → Load Temporary Add-on → `manifest.json`.
3. Click the toolbar icon → ⚙ → enter your server URL + credentials.

> The extension requests host permission for your server origin on first connect
> (MV3 security model).

## Build the mobile app (iOS / Android)

Requires the Expo toolchain (`npx expo` + Xcode or Android Studio).

```bash
cd apps/mobile
pnpm install
npx expo start          # scan the QR code with Expo Go, or press i / a
```

TOTP works offline on device via the pure-JS HMAC fallback in `packages/core`.

## Production deployment

### Option A — Docker (recommended)

```bash
cd docker
export ENCRYPTION_KEY=$(node -e "console.log(require('crypto').randomBytes(32).toString('base64'))")
docker compose up -d
```

Put it behind **Caddy** (see `docker/Caddyfile`) or any reverse proxy so it gets
HTTPS — required for mobile + extension use on non-localhost servers.

### Option B — bare metal (any OS)

```bash
cd apps/server
npm i -g pnpm && pnpm install && pnpm build
ENCRYPTION_KEY=<32-byte-base64> DATA_DIR=/var/lib/selfhostauth PORT=8787 pnpm start
```

systemd unit included at `docker/selfhostauth.service`.

## Configuration

| Env var | Default | Purpose |
|---------|---------|---------|
| `PORT` | `8787` | HTTP port |
| `HOST` | `0.0.0.0` | Bind address |
| `DATA_DIR` | `./data` | SQLite DB + auto-generated `encryption.key` |
| `ENCRYPTION_KEY` | auto-generated | 32-byte base64 AES key; set it for multi-instance/backup stability |
| `ALLOW_REGISTRATION` | `true` | Disable open signup for a private server |
| `SESSION_TTL_DAYS` | `30` | Session lifetime |
| `RATE_LIMIT_PER_MINUTE` | `20` | Per-IP auth attempt limit |

## Security model

- Passwords: `scrypt` (N=16384, r=8, p=1) with per-user salt.
- Secrets at rest: AES-256-GCM per item; the key is the server's `encryption.key`.
- Sessions: random 64-char tokens, stored only as SHA-256 hashes, sliding expiry.
- Optional account 2FA: TOTP required at login when enabled.
- In transit: TLS via your reverse proxy; the API is unauthenticated-free otherwise.
- Clients compute codes locally — the server is never asked for codes during normal
  use (the `/verify` endpoint exists for testing/CI).

**Roadmap:** client-side E2E encryption (vault unlocked by a master password),
WebAuthn passkeys, family sharing, FIDO/steam/email OTP types, and platform
notifications. PRs welcome.

## Development

```bash
pnpm build             # build all packages/apps
pnpm test              # core (RFC vectors) + server API tests
pnpm dev:server        # server watch mode
pnpm dev:desktop       # electron + vite HMR
pnpm dev:extension     # rebuild extension on change
pnpm dev:mobile        # expo start
```

The core library is validated against the **official RFC 4226 and RFC 6238 test
vectors** for SHA-1, SHA-256 and SHA-512, plus RFC 4231 HMAC vectors for the
pure-JS fallback path used on React Native.

## License

MIT — see `LICENSE`.