// Release gate: the published tarball must contain exactly what the
// allowlist permits. Anything unexpected (env files, audit data, raw
// sources, local config) fails the publish.
import { execSync } from "node:child_process";

const ALLOWED = [
  /^package\.json$/u,
  /^README\.md$/u,
  /^SECURITY\.md$/u,
  /^CHANGELOG\.md$/u,
  /^LICENSE$/u,
  /^config\/broker\.example\.yaml$/u,
  /^dist\/src\/[a-z-]+\.(js|d\.ts|js\.map|d\.ts\.map)$/u,
];

const REQUIRED = [
  "dist/src/stdio.js",
  "dist/src/server.js",
  "dist/src/engine.js",
  "dist/src/policy.js",
  "dist/src/canonical.js",
  "dist/src/redact.js",
  "config/broker.example.yaml",
  "SECURITY.md",
];

const FORBIDDEN_PATTERNS = [/\.env/u, /^data\//u, /^test\//u, /^src\//u, /broker\.yaml$/u, /approvals\.json$/u];

const output = execSync("npm pack --dry-run --json", { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
const report = JSON.parse(output);
const files = report[0].files.map((file) => file.path.replace(/\\/gu, "/"));

const problems = [];
for (const file of files) {
  if (FORBIDDEN_PATTERNS.some((pattern) => pattern.test(file))) {
    problems.push(`forbidden file in pack: ${file}`);
    continue;
  }
  if (!ALLOWED.some((pattern) => pattern.test(file))) {
    problems.push(`file not on the pack allowlist: ${file}`);
  }
}
for (const required of REQUIRED) {
  if (!files.includes(required)) problems.push(`required file missing from pack: ${required}`);
}

if (problems.length > 0) {
  console.error("verify:pack FAILED");
  for (const problem of problems) console.error(`  - ${problem}`);
  process.exit(1);
}
console.log(`verify:pack OK (${files.length} files, all on the allowlist)`);
