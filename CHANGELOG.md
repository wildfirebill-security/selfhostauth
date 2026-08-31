# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
- Vulnerability transparency: `VULNERABILITIES.md` now generated on every push via `.github/workflows/vuln.yml` (source `pnpm audit` + `trivy fs`, built executables hash/scan, Docker `trivy image`). Run `pnpm vuln:check` locally.

## [0.1.6] - 2026-08-31

### Fixed
- **Mobile (OSS):** Migrated from Expo (proprietary EAS) to **bare React Native 0.76** (100% MIT). Removed `expo`, `expo-clipboard`, `expo-status-bar`, `eas.json`, `mobile-eas.yml`; added `@react-native-clipboard/clipboard`, `@react-native/babel-preset`, `metro.config.js`, `index.js` + `app.json` (bare). CI now bootstraps native projects via `@react-native-community/cli` and builds APK (Gradle) / iOS simulator (Xcode) without Expo.
- **Web:** Added browser Web vault (`apps/web` — Vite SPA) served from the server at `/` via `@fastify/static` (SPA fallback) and included in Docker image (`docker/Dockerfile` builds `apps/web`).
- **Vulnerabilities:** Fixed checker false positives — secrets `git grep` now requires `key\s*[:=]\s*['"]?[value]{8,}` and ignores `*.md`/`VULNERABILITIES.md`/`.github`, so HTML `type="password"` no longer flags.
- **Docs:** Updated `README.md` (Web vault section, bare RN instructions, CI description) and `.gitignore` (`apps/web/dist/`, `apps/extension/selfhostauth-extension.zip`).

## [0.1.5] - 2026-08-31

### Fixed
- **Release assets:** `release-desktop.yml` used `apps/desktop/dist/installers/**` which published 107 files (unpacked `linux-unpacked/`, `win-unpacked/`, `.pak`, `.dll`, etc.) to GitHub Releases. Changed to explicit globs `*.exe, *.dmg, *.AppImage, *.deb, *.rpm, *.blockmap, *.yml` + extension zip. Cleaned `v0.1.4` release (107 → 6 assets).
- **Version alignment:** Bumped all workspace `package.json` versions to `0.1.5` so artifact names match tag (were stuck at `0.1.0`).

## [0.1.4] - 2026-08-31

### Fixed
- **Releases:** Added `contents: write` + `softprops/action-gh-release@v2` to `release-desktop.yml` so installers are attached to the GitHub Release (previously only workflow artifacts). Also build/publish extension zip on linux job.

## [0.1.3] - 2026-08-31

### Fixed
- **Desktop Linux packaging:** `electron-builder` FpmTarget used scoped name `@selfhostauth/desktop` in deb/rpm artifact path (`…/installers/@selfhostauth/desktop_*.deb` → parent dir missing). Set `executableName: selfhostauth` and `artifactName: "${productName}-${version}-${arch}.${ext}"` in `apps/desktop/electron-builder.yml`.

## [0.1.2] - 2026-08-31

### Fixed
- **Desktop Linux packaging:** FpmTarget requires `homepage` and `author` — added to `apps/desktop/package.json` (was `you@example.com` placeholder, now `https://github.com/wildfirebill-security/selfhostauth`).

## [0.1.1] - 2026-08-31

### Fixed
- **Build:** Vite failed to resolve workspace packages (`@selfhostauth/client`, `@selfhostauth/core`) with `commonjs--resolver` error — added `"import"` condition to `exports` in both packages.
- **CI:** `ci.yml` ran `typecheck` before `build` so `tsc` couldn't find declarations — now `build` before `typecheck`.
- **Mobile:** `mobile-local.yml` only ran on `workflow_dispatch`; EAS workflow failed without `EXPO_TOKEN` — made it a warning + `SKIP_EAS` instead of hard fail.

## [0.1.0] - 2026-08-30

### Added
- Initial release of **SelfHostAuth** — self-hosted TOTP/HOTP authenticator.
- **Server:** Fastify + `node:sqlite` (WAL), `scrypt` passwords, SHA-256 hashed tokens, AES-256-GCM vault at rest, revision-based sync (push/pull + tombstones), rate limiting, optional account TOTP 2FA.
- **Core:** RFC 6238/4226/4231 vectors, otpauth parsing, base32, WebCrypto + pure-JS HMAC fallback.
- **Client:** Typed `SelfhostAuthClient` (`fetch`, works in Node/browsers/RN).
- **Desktop:** Electron (Win NSIS, macOS DMG, Linux AppImage/deb/rpm), live countdown, search, otpauth import.
- **Extension:** MV3 (Chrome/Edge/Firefox) with popup + options + 5-min background sync.
- **Mobile:** Expo 52 (later replaced by bare RN) for iOS/Android.
- **Deploy:** `docker/Dockerfile` (multi-stage, <50MB), `docker-compose.yml`, `Caddyfile`, `systemd` unit.
- **CI/CD:** `ci.yml` (Ubuntu/Win/macOS × Node 22/24), `release-desktop.yml`, `docker-publish.yml` (GHCR), `mobile-local.yml` / `mobile-eas.yml`.
- **Docs & compliance:** SEO-optimized `README.md`, `LICENSE` (MIT), `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`, `SECURITY.md`, issue/PR templates, `FUNDING.yml`, `dependabot.yml` — GitHub community health 50% → 100%.
- **Security:** `VULNERABILITIES.md` (100% open) via `scripts/check-vulnerabilities.mjs` + `vuln.yml` (source/built/Docker) and `pnpm vuln:check`.

[Unreleased]: https://github.com/wildfirebill-security/selfhostauth/compare/v0.1.6...HEAD
[0.1.6]: https://github.com/wildfirebill-security/selfhostauth/compare/v0.1.5...v0.1.6
[0.1.5]: https://github.com/wildfirebill-security/selfhostauth/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/wildfirebill-security/selfhostauth/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/wildfirebill-security/selfhostauth/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/wildfirebill-security/selfhostauth/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/wildfirebill-security/selfhostauth/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/wildfirebill-security/selfhostauth/releases/tag/v0.1.0
