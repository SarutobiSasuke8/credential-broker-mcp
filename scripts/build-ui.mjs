// Builds the key manager page: compiles src/ui/*.ts to dist/ui and copies
// the static HTML, CSS and SVG assets beside it. The key manager serves these files
// itself on loopback under its CSP; nothing is fetched from anywhere else.
import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, readdirSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const source = path.join(root, "src", "ui");
const out = path.join(root, "dist", "ui");
const require = createRequire(import.meta.url);
const tsc = require.resolve("typescript/bin/tsc");

const noEmit = process.argv.includes("--noEmit");
execFileSync(process.execPath, [tsc, "-p", path.join(source, "tsconfig.json"), ...(noEmit ? ["--noEmit"] : [])], { stdio: "inherit" });
if (noEmit) process.exit(0);

mkdirSync(out, { recursive: true });
for (const name of readdirSync(source)) {
  if (/\.(html|css|svg)$/u.test(name)) copyFileSync(path.join(source, name), path.join(out, name));
}
