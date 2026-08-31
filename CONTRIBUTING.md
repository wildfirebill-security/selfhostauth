# Contributing to SelfHostAuth

Thanks for considering a contribution — every fix, feature, and doc tweak helps.

## Quick start

```bash
corepack enable
pnpm install
pnpm build        # topological — builds packages before apps
pnpm typecheck
pnpm test         # 12 core (RFC vectors) + 9 server API = 21 tests
```

- **Node** ≥ 22, **pnpm** ≥ 10.13
- **Desktop:** `pnpm --filter @selfhostauth/desktop dev` (Electron + Vite HMR)
- **Web:** `pnpm --filter @selfhostauth/web dev` (Vite on :5174, proxies /api)
- **Extension:** `pnpm --filter @selfhostauth/extension dev`
- **Mobile:** `pnpm --filter @selfhostauth/mobile start` (bare React Native)
- **Server:** `pnpm --filter @selfhostauth/server dev` (http://127.0.0.1:8787)

Native mobile/extension builds require platform toolchains (Xcode / Android Studio).
See README for per-platform instructions.

## Project structure

```
packages/core      TOTP/HOTP, otpauth, crypto — zero deps, runs everywhere
packages/client    Typed API client
apps/server        Fastify + node:sqlite — the sync brain + Web UI host
apps/web           Web vault (Vite SPA at /)
apps/desktop       Electron (Win/Mac/Linux)
apps/extension     MV3 (Chrome/Edge/Firefox)
apps/mobile        Bare React Native 0.76 (iOS/Android, 100% OSS)
docker             Dockerfile, compose, Caddyfile, systemd
```

## Pull requests

1. **Branch** from `main`: `feat/my-thing` / `fix/bug-123`
2. **Conventional Commits** — `feat:`, `fix:`, `docs:`, `chore:` etc.
3. Keep diffs focused; add/update tests for behavior changes
4. Ensure `pnpm build && pnpm typecheck && pnpm test` passes
5. Describe *why*, link issues, add screenshots for UI changes

PRs run on **Ubuntu / Windows / macOS × Node 22/24** (see `.github/workflows/ci.yml`).
Desktop installers + Docker image publish on tags `v*`.

## Commit signing

Signed commits are welcome but not required.

## Reporting bugs / requesting features

Use the **issue templates** — include steps to reproduce, expected vs actual,
server/client versions, and logs where useful. For security issues, see
[SECURITY.md](SECURITY.md) — **do not** file a public issue.

## Code style

- TypeScript `strict`, `noUncheckedIndexedAccess`
- Prettier-ish formatting; keep imports sorted
- No new runtime deps in `packages/core` (must stay portable to RN)

## License

By contributing you agree your contributions are licensed under the same [MIT](LICENSE) license.
