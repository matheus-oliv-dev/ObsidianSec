#!/usr/bin/env node
import { spawn } from "node:child_process";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);

const ANSI = {
  yellow: "\x1b[33m",
  cyan: "\x1b[36m",
  bold: "\x1b[1m",
  reset: "\x1b[0m",
};

console.log(`${ANSI.yellow}${ANSI.bold}╔══════════════════════════════════════════════════════════════════════╗`);
console.log(`║  ⚡ NOTICE: ObsidianSec has officially evolved into ChimeraGuard!    ║`);
console.log(`║  Forwarding execution seamlessly to chimeraguard v1.5.0...           ║`);
console.log(`║  Please update your CI/CD pipelines to: npx chimeraguard <command>   ║`);
console.log(`╚══════════════════════════════════════════════════════════════════════╝${ANSI.reset}\n`);

const args = process.argv.slice(2);

try {
  const chimeraguardPkgPath = require.resolve("chimeraguard/package.json");
  const chimeraguardDir = chimeraguardPkgPath.replace(/[\\/]package\.json$/, "");
  const cliPath = chimeraguardDir + "/bin/cli.mjs";
  const child = spawn(process.execPath, [cliPath, ...args], { stdio: "inherit" });
  child.on("exit", (code) => process.exit(code ?? 0));
} catch {
  if (process.platform === "win32") {
    const child = spawn("cmd.exe", ["/c", "npx", "chimeraguard", ...args], { stdio: "inherit" });
    child.on("exit", (code) => process.exit(code ?? 0));
  } else {
    const child = spawn("npx", ["chimeraguard", ...args], { stdio: "inherit" });
    child.on("exit", (code) => process.exit(code ?? 0));
  }
}
