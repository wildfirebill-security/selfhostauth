import { execSync } from "node:child_process";
import { existsSync, rmSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const dist = join(root, "dist");
const zipPath = join(root, "selfhostauth-extension.zip");

if (!existsSync(dist)) {
  console.error("dist/ does not exist — run `pnpm build` first.");
  process.exit(1);
}

rmSync(zipPath, { force: true });

try {
  execSync(
    `powershell -NoProfile -Command "Compress-Archive -Path '${dist.replace(/'/g, "''")}\\*' -DestinationPath '${zipPath.replace(/'/g, "''")}' -Force"`,
    { stdio: "inherit" },
  );
  console.log("zipped →", zipPath);
} catch {
  console.log("Zip failed; dist/ is still ready to load as an unpacked extension.");
  process.exit(1);
}