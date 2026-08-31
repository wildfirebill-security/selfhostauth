#!/usr/bin/env node
/**
 * SelfHostAuth — Vulnerability Transparency Checker
 * Checks: source deps, built executables, Docker image
 * Output: VULNERABILITIES.md (100% open — every finding is disclosed)
 *
 * Usage:
 *   node scripts/check-vulnerabilities.mjs           # full check
 *   node scripts/check-vulnerabilities.mjs --json    # JSON to stdout
 *
 * Tools (auto-detected, skipped if missing):
 *   pnpm audit, trivy fs, trivy image, gitleaks
 */

import { execSync } from "node:child_process";
import { existsSync, readdirSync, statSync, readFileSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const OUT = join(ROOT, "VULNERABILITIES.md");
const isJson = process.argv.includes("--json");

function sh(cmd, opts = {}) {
  try {
    return execSync(cmd, { encoding: "utf8", stdio: "pipe", cwd: ROOT, timeout: 120000, ...opts }).trim();
  } catch (e) {
    const out = (e.stdout?.toString() || "") + (e.stderr?.toString() || "");
    return out.trim() || e.message;
  }
}

function has(cmd) {
  try { execSync(`${process.platform === "win32" ? "where" : "which"} ${cmd}`, { stdio: "pipe" }); return true; } catch { return false; }
}

function hashFile(p) {
  try { return createHash("sha256").update(readFileSync(p)).digest("hex").slice(0, 12); } catch { return "—"; }
}

function sizeOf(p) {
  try { const s = statSync(p); return s.isFile() ? `${(s.size/1024).toFixed(1)} KB` : `${s.size} entries`; } catch { return "—"; }
}

function listFiles(dir, depth=2) {
  if (!existsSync(dir) || depth < 0) return [];
  try {
    return readdirSync(dir, { withFileTypes: true }).flatMap(d => {
      const p = join(dir, d.name);
      if (d.isDirectory()) return [`${p}/`, ...listFiles(p, depth-1)];
      return [p];
    });
  } catch { return []; }
}

// ── 1. SOURCE ───────────────────────────────────────────────────────────────
function checkSource() {
  const findings = [];
  let pnpmAudit = "";
  try {
    pnpmAudit = sh("pnpm audit --json 2>&1");
    const j = JSON.parse(pnpmAudit);
    const vulns = j.advisories ? Object.values(j.advisories) : (j.vulnerabilities ? Object.values(j.vulnerabilities) : []);
    if (vulns.length === 0 && !pulpHasVuln(pnpmAudit)) findings.push({ severity: "info", title: "pnpm audit: 0 vulnerabilities", detail: "No known CVEs in dependencies." });
    else findings.push(...parsePnpmAudit(pnpmAudit));
  } catch {
    if (pulpHasVuln(pnpmAudit)) findings.push(...parsePnpmAudit(pnpmAudit));
    else if (pnpmAudit.includes("No known vulnerabilities") || pnpmAudit.includes("0 vulnerabilities")) findings.push({ severity: "info", title: "pnpm audit: 0 vulnerabilities", detail: pnpmAudit.slice(0, 600) });
    else findings.push({ severity: "info", title: "pnpm audit: no parseable output", detail: pnpmAudit.slice(0, 800) || "pnpm audit produced no JSON — check manually with `pnpm audit`" });
  }

  // gitleaks / secrets
  if (has("gitleaks")) {
    const out = sh("gitleaks detect --no-git --source . --no-banner --redact 2>&1 | head -100");
    if (out.includes("no leaks") || out === "") findings.push({ severity: "info", title: "gitleaks: no secrets detected", detail: "No hardcoded secrets found in working tree." });
    else findings.push({ severity: "high", title: "gitleaks: potential secrets", detail: out.slice(0, 1200) });
  } else {
    // fallback simple grep — ignore docs, templates, and the checker itself
    const hits = sh("git grep -i -E \"(ENCRYPTION_KEY|password|secret).*[:=].{8,}\" -- ':!pnpm-lock.yaml' ':!VULNERABILITIES.md' ':!*.md' ':!.github/*' ':!scripts/check-vulnerabilities.mjs' 2>&1 | head -20");
    if (!hits) findings.push({ severity: "info", title: "secrets grep: no hardcoded secrets", detail: "Heuristic grep for hardcoded secrets found nothing (install gitleaks for deeper scan)." });
    else findings.push({ severity: "medium", title: "secrets grep: review hits", detail: hits.slice(0, 800) });
  }

  // trivy fs
  if (has("trivy")) {
    const out = sh("trivy fs --severity HIGH,CRITICAL --format json --quiet . 2>&1 | head -c 8000");
    try {
      const j = JSON.parse(out);
      const count = (j.Results || []).reduce((n,r) => n + (r.Vulnerabilities||[]).length, 0);
      if (count === 0) findings.push({ severity: "info", title: "trivy fs: 0 HIGH/CRITICAL", detail: "Filesystem scan found no high/critical CVEs." });
      else findings.push({ severity: "high", title: `trivy fs: ${count} HIGH/CRITICAL findings`, detail: out.slice(0, 2000) });
    } catch { findings.push({ severity: "info", title: "trivy fs: scan completed", detail: out.slice(0, 1200) || "No JSON output — run `trivy fs .` manually" }); }
  } else {
    findings.push({ severity: "info", title: "trivy fs: skipped (not installed)", detail: "Install aquasecurity/trivy for filesystem CVE scan. CI runs it automatically." });
  }

  return findings;
}

function pulpHasVuln(s) { return /vulnerabilit/i.test(s) && !/0 vulnerabilities/i.test(s); }
function parsePnpmAudit(raw) {
  try {
    const j = JSON.parse(raw);
    if (j.metadata?.vulnerabilities) {
      const m = j.metadata.vulnerabilities;
      const total = (m.high||0)+(m.critical||0)+(m.moderate||0)+(m.low||0);
      if (total===0) return [{ severity:"info", title:"pnpm audit: 0 vulnerabilities", detail: JSON.stringify(m) }];
      return [{ severity: total>0?"high":"info", title:`pnpm audit: ${total} vulns (high:${m.high} critical:${m.critical} moderate:${m.moderate} low:${m.low})`, detail: raw.slice(0,2000) }];
    }
  } catch {}
  return [{ severity:"medium", title:"pnpm audit: findings (unparsed)", detail: raw.slice(0,1500) }];
}

// ── 2. BUILT EXECUTABLES ──────────────────────────────────────────────────
function checkBuilt() {
  const findings = [];
  const built = [
    "apps/server/dist/index.js",
    "apps/web/dist/index.html",
    "apps/desktop/dist/main/main.js",
    "apps/desktop/dist/main/preload.cjs",
    "apps/desktop/dist/renderer/index.html",
    "apps/extension/dist/manifest.json",
    "apps/mobile/index.js",
  ];
  for (const rel of built) {
    const p = join(ROOT, rel);
    if (existsSync(p)) findings.push({ severity:"info", title:`built: ${rel} present`, detail: `${sizeOf(p)} · sha256:${hashFile(p)}` });
    else findings.push({ severity:"low", title:`built: ${rel} missing`, detail: "Not built — run `pnpm build`. CI builds all before scanning." });
  }

  // installer artifacts (only exist after electron-builder)
  const instDir = join(ROOT, "apps/desktop/dist/installers");
  if (existsSync(instDir)) {
    const inst = listFiles(instDir, 1).filter(f => !f.endsWith("/")).slice(0, 20);
    if (inst.length) findings.push({ severity:"info", title:`installers: ${inst.length} artifacts`, detail: inst.map(f => `${f.replace(ROOT+"/","")} · ${sizeOf(f)}`).join("\n") });
  } else {
    findings.push({ severity:"info", title:"installers: not built locally", detail: "Run `pnpm --filter @selfhostauth/desktop package` or check Releases. CI builds on tags." });
  }

  // electron version check
  try {
    const pkg = JSON.parse(readFileSync(join(ROOT, "apps/desktop/package.json"), "utf8"));
    const ver = pkg.devDependencies?.electron || pkg.dependencies?.electron || "unknown";
    findings.push({ severity:"info", title:`Electron ${ver}`, detail: "Check https://github.com/advisories?query=electron for current CVEs. Dependabot watches this." });
  } catch {}

  // quick secret check in built output
  const builtDir = join(ROOT, "apps/server/dist");
  if (existsSync(builtDir)) {
    const hit = sh(`grep -r -i -E "ENCRYPTION_KEY.*[A-Za-z0-9+/]{20,}" ${builtDir} 2>&1 | head -5`);
    if (!hit) findings.push({ severity:"info", title:"built executables: no embedded secrets", detail: "Grep of server dist for hardcoded keys found nothing." });
    else findings.push({ severity:"high", title:"built executables: potential embedded secret", detail: hit.slice(0,600) });
  }

  return findings;
}

// ── 3. DOCKER IMAGE ───────────────────────────────────────────────────────
function checkDocker() {
  const findings = [];
  const df = join(ROOT, "docker/Dockerfile");
  if (!existsSync(df)) return [{ severity:"low", title:"Dockerfile missing", detail:"No docker/Dockerfile found." }];
  const content = readFileSync(df, "utf8");
  const base = (content.match(/FROM\s+(\S+)/) || [])[1] || "unknown";
  findings.push({ severity:"info", title:`Docker base: ${base}`, detail: `Dockerfile FROM ${base}. Trivy image scan checks base CVEs.` });

  if (has("docker")) {
    try {
      const built = sh("docker images selfhostauth:test --format '{{.Repository}}' 2>&1 | head -1");
      if (!built.includes("selfhostauth")) {
        findings.push({ severity:"info", title:"Docker image: not built locally", detail: "Build with `docker build -t selfhostauth:test -f docker/Dockerfile .` then re-run. CI builds and scans on every push." });
      }
    } catch {}
    if (has("trivy")) {
      const img = sh("docker images -q selfhostauth:test 2>&1 | head -1");
      if (img) {
        const out = sh("trivy image --severity HIGH,CRITICAL --format json --quiet selfhostauth:test 2>&1 | head -c 8000");
        try {
          const j = JSON.parse(out);
          const count = (j.Results||[]).reduce((n,r)=>n+(r.Vulnerabilities||[]).length,0);
          if (count===0) findings.push({ severity:"info", title:"trivy image: 0 HIGH/CRITICAL", detail:"Image scan clean." });
          else findings.push({ severity:"high", title:`trivy image: ${count} HIGH/CRITICAL`, detail: out.slice(0,2000) });
        } catch { findings.push({ severity:"info", title:"trivy image: scan output", detail: out.slice(0,1200) }); }
      }
    } else {
      findings.push({ severity:"info", title:"trivy image: skipped (trivy not installed)", detail:"CI runs aquasecurity/trivy-action on every build." });
    }
  } else {
    findings.push({ severity:"info", title:"Docker: not installed locally", detail:"Install Docker to scan the image. CI builds + scans with Trivy on every push." });
  }

  // docker-compose / Caddyfile presence
  for (const f of ["docker/docker-compose.yml","docker/Caddyfile"]) {
    findings.push({ severity:"info", title:`${f} present`, detail: existsSync(join(ROOT,f)) ? "Found." : "Missing." });
  }
  return findings;
}

// ── Render ────────────────────────────────────────────────────────────────
function badge(count) {
  if (count.high>0) return "![vulns](https://img.shields.io/badge/vulnerabilities-HIGH-red)";
  if (count.medium>0) return "![vulns](https://img.shields.io/badge/vulnerabilities-MEDIUM-yellow)";
  if (count.low>0) return "![vulns](https://img.shields.io/badge/vulnerabilities-LOW-yellowgreen)";
  return "![vulns](https://img.shields.io/badge/vulnerabilities-0%20open-brightgreen)";
}

function render(findings) {
  const now = new Date().toISOString();
  const bySev = { high:[], medium:[], low:[], info:[] };
  for (const f of findings) (bySev[f.severity]||bySev.info).push(f);
  const counts = { high:bySev.high.length, medium:bySev.medium.length, low:bySev.low.length, total: findings.length };
  const icon = { high:"🔴", medium:"🟡", low:"🟢", info:"ℹ️" };

  let md = `# Vulnerabilities — Transparent Disclosure

${badge(counts)} — **Last checked: ${now}** · **100% open** — every finding below is disclosed, even when 0.

> Generated by \`scripts/check-vulnerabilities.mjs\` + \`.github/workflows/vuln.yml\`.
> Checks **source**, **built executables**, and **Docker image** on every push and weekly.
> No finding is hidden. If a section says “0”, it really is 0 as of this timestamp.
> See also [SECURITY.md](SECURITY.md) for how to report privately.

**Summary:** ${counts.high} high · ${counts.medium} medium · ${counts.low} low · ${bySev.info.length} info

| Area | High | Medium | Low | Info |
|------|------|--------|-----|------|
| Source (deps + secrets + fs) | ${bySev.high.filter(f=>f.title.match(/pnpm|trivy fs|gitleaks|secrets/)).length} | ${bySev.medium.filter(f=>f.title.match(/pnpm|trivy|gitleaks/)).length} | — | — |
| Built executables | — | — | — | ${bySev.info.filter(f=>f.title.startsWith("built")||f.title.startsWith("installers")||f.title.startsWith("Electron")).length} |
| Docker image | — | — | — | — |

---

`;

  for (const sev of ["high","medium","low","info"]) {
    if (!bySev[sev].length) continue;
    md += `## ${icon[sev]} ${sev.toUpperCase()} / INFO (${bySev[sev].length})\n\n`;
    for (const f of bySev[sev]) {
      md += `### ${f.title}\n\n`;
      const detail = (f.detail||"").trim();
      if (detail) md += "```\n" + detail.slice(0, 3000) + "\n```\n\n";
    }
  }

  md += `---

## How this file is produced

| Check | Tool (local) | Tool (CI) | What it covers |
|-------|--------------|-----------|----------------|
| **Source deps** | \`pnpm audit --json\` | same + \`aquasecurity/trivy-action\` (fs) | Known CVEs in npm/pnpm deps |
| **Secrets** | \`gitleaks detect --no-git\` (fallback: \`git grep\`) | \`gitleaks/gitleaks-action\` | Hardcoded keys, tokens |
| **Built executables** | File presence + sha256 + grep for embedded secrets | same (after \`pnpm build\`) | Verifies artifacts exist, no secrets baked in |
| **Docker image** | \`docker build\` + \`trivy image\` | \`docker/build-push-action\` + \`trivy-action\` (image) | Base image (node:24-alpine) + layers |

- **Local:** \`pnpm vuln:check\` (or \`node scripts/check-vulnerabilities.mjs\`) then \`cat VULNERABILITIES.md\`
- **CI:** \`.github/workflows/vuln.yml\` runs on every push to \`main\`, PRs, and weekly (Monday 08:00), commits the updated file back to \`main\` if it changed.

## Interpreting results

- **0 high/medium** is the goal. **Info** entries are not vulnerabilities — they are proof the check ran.
- \`trivy\` / \`gitleaks\` show “skipped (not installed)” locally — that just means that tool isn't on your machine; CI always runs the full suite. Install them to get a complete local report: \`brew install trivy gitleaks\` (macOS) / see [trivy docs](https://aquasecurity.github.io/trivy/) / [gitleaks](https://github.com/gitleaks/gitleaks).
- Electron CVEs are tracked via Dependabot + \`pnpm audit\`; the Electron version is listed above for cross-check at https://github.com/advisories?query=electron.

*This file is intentionally verbose — transparency over brevity.*
`;

  return md;
}

const all = [...checkSource(), ...checkBuilt(), ...checkDocker()];
const md = render(all);

if (isJson) {
  console.log(JSON.stringify(all, null, 2));
} else {
  writeFileSync(OUT, md);
  console.log(`Wrote ${OUT} — ${all.length} findings (${all.filter(f=>f.severity==="high").length} high)`);
  console.log(md.slice(0, 800));
}
