import { build } from "esbuild";
import { cpSync, mkdirSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const src = join(root, "src");
const out = join(root, "dist");
const watch = process.argv.includes("--watch");

rmSync(out, { recursive: true, force: true });
mkdirSync(out, { recursive: true });

// Static assets
cpSync(join(root, "manifest.json"), join(out, "manifest.json"));
cpSync(join(root, "icons"), join(out, "icons"), { recursive: true });
for (const f of ["options.html", "popup.html", "options.css", "popup.css"]) {
  cpSync(join(src, f), join(out, f));
}

const common = {
  bundle: true,
  format: "iife",
  target: "chrome110",
  sourcemap: false,
  logLevel: "info",
};

if (watch) {
  const ctx = await build({
    ...common,
    entryPoints: {
      options: join(src, "options.ts"),
      popup: join(src, "popup.ts"),
      background: join(src, "background.ts"),
    },
    outdir: out,
  });
  await ctx.watch();
} else {
  await build({
    ...common,
    entryPoints: {
      options: join(src, "options.ts"),
      popup: join(src, "popup.ts"),
      background: join(src, "background.ts"),
    },
    outdir: out,
  });
}

console.log("extension built →", out);