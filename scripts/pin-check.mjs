#!/usr/bin/env node
// pin-check: report floating runtime and supply-chain references.
//
// Checks (dependency-free, read-only):
//   - Dockerfile / Containerfile `FROM` lines without an `@sha256:` digest
//   - Compose `image:` references without a digest (images built locally by
//     a service with `build:` are skipped)
//   - package.json `engines.node` ranges (anything but an exact x.y.z)
//   - workflow / composite action `uses:` refs that are not a full 40-char SHA
//   - git dependencies (github:, git+, owner/repo, ...) without a full commit SHA
//
// Default is REPORT mode: GitHub `::warning::` annotations, a markdown table in
// $GITHUB_STEP_SUMMARY (or stdout locally), exit 0.
// Pass `--strict` (or set PIN_CHECK_STRICT=1) to exit 1 when anything floats.
// Pass `--json` to print the findings as JSON instead of the table.
import { existsSync, readdirSync, readFileSync, appendFileSync } from "node:fs";
import { join, relative, sep } from "node:path";

const args = new Set(process.argv.slice(2));
const strict = args.has("--strict") || process.env.PIN_CHECK_STRICT === "1";
const asJson = args.has("--json");
const root = process.cwd();

const SKIP_DIRS = new Set([".git", "node_modules", "dist", "coverage", "data", ".next", ".turbo"]);
const SHA40 = /^[0-9a-f]{40}$/u;
const findings = [];

function rel(path) {
  return relative(root, path).split(sep).join("/");
}

function walk(dir, out = []) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name)) walk(join(dir, entry.name), out);
    } else if (entry.isFile()) {
      out.push(join(dir, entry.name));
    }
  }
  return out;
}

function add(kind, file, line, ref, detail) {
  findings.push({ kind, file: rel(file), line, ref, detail });
}

function lineOf(text, index) {
  return text.slice(0, index).split("\n").length;
}

// --- Dockerfiles -----------------------------------------------------------
function checkDockerfile(file) {
  const lines = readFileSync(file, "utf8").split(/\r?\n/u);
  const stages = new Set();
  lines.forEach((raw, i) => {
    const m = raw.match(/^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?/iu);
    if (!m) return;
    const image = m[1];
    if (m[2]) stages.add(m[2].toLowerCase());
    if (image === "scratch" || stages.has(image.toLowerCase())) return;
    if (image.includes("@sha256:")) return;
    const detail = image.includes("$")
      ? "base image is set from a build ARG; cannot verify a digest"
      : "base image has no @sha256: digest";
    add("docker-from", file, i + 1, image, detail);
  });
}

// --- Compose files ---------------------------------------------------------
function checkCompose(file) {
  const lines = readFileSync(file, "utf8").split(/\r?\n/u);
  const services = [];
  let inServices = false;
  let current = null;
  let serviceIndent = -1;
  lines.forEach((raw, i) => {
    if (/^\s*(#|$)/u.test(raw)) return;
    const indent = raw.match(/^\s*/u)[0].length;
    if (indent === 0) {
      inServices = /^services:\s*$/u.test(raw);
      current = null;
      serviceIndent = -1;
      return;
    }
    if (!inServices) return;
    if (serviceIndent === -1) serviceIndent = indent;
    if (indent === serviceIndent) {
      current = { build: false, image: null, line: 0 };
      services.push(current);
      return;
    }
    if (!current || indent <= serviceIndent) return;
    const build = raw.match(/^\s*build\s*:/u);
    if (build) current.build = true;
    const img = raw.match(/^\s*image\s*:\s*["']?([^"'\s#]+)/u);
    if (img) {
      current.image = img[1];
      current.line = i + 1;
    }
  });
  const local = new Set(services.filter((s) => s.build && s.image).map((s) => s.image));
  for (const s of services) {
    if (!s.image || s.build || local.has(s.image)) continue;
    if (s.image.includes("@sha256:")) continue;
    add("compose-image", file, s.line, s.image, "compose image has no @sha256: digest");
  }
}

// --- package.json ----------------------------------------------------------
const GIT_SPEC = /^(?:github:|gitlab:|bitbucket:|gist:|git\+|git:\/\/|git@|https?:\/\/(?:www\.)?(?:github|gitlab|bitbucket)\.(?:com|org)\/)/u;
const SHORTHAND = /^[A-Za-z0-9][\w.-]*\/[\w.-]+(?:#.*)?$/u;

function checkPackageJson(file) {
  const text = readFileSync(file, "utf8");
  let pkg;
  try {
    pkg = JSON.parse(text);
  } catch {
    return;
  }
  const engine = pkg.engines?.node;
  if (typeof engine === "string" && !/^v?\d+\.\d+\.\d+$/u.test(engine.trim())) {
    const idx = text.search(/"engines"\s*:/u);
    add("engines-node", file, idx >= 0 ? lineOf(text, idx) : 1, engine, "engines.node is a range, not an exact version");
  }
  for (const field of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]) {
    for (const [name, spec] of Object.entries(pkg[field] ?? {})) {
      if (typeof spec !== "string") continue;
      const isGit = GIT_SPEC.test(spec) || (SHORTHAND.test(spec) && !spec.startsWith("file:") && !spec.startsWith("npm:"));
      if (!isGit) continue;
      const ref = spec.includes("#") ? spec.slice(spec.lastIndexOf("#") + 1) : "";
      if (SHA40.test(ref)) continue;
      const idx = text.indexOf(`"${name}"`);
      add("git-dependency", file, idx >= 0 ? lineOf(text, idx) : 1, `${name}@${spec}`, ref ? `git ref "${ref}" is not a full commit SHA` : "git dependency has no commit SHA");
    }
  }
}

// --- workflows and composite actions ---------------------------------------
function checkWorkflow(file) {
  const lines = readFileSync(file, "utf8").split(/\r?\n/u);
  lines.forEach((raw, i) => {
    const m = raw.match(/^\s*(?:-\s*)?uses\s*:\s*["']?([^\s"'#]+)/u);
    if (!m) return;
    const target = m[1];
    if (target.startsWith("./")) return;
    if (target.startsWith("docker://")) {
      if (!target.includes("@sha256:")) add("action-uses", file, i + 1, target, "docker action has no @sha256: digest");
      return;
    }
    const at = target.lastIndexOf("@");
    const ref = at >= 0 ? target.slice(at + 1) : "";
    if (SHA40.test(ref)) return;
    add("action-uses", file, i + 1, target, ref ? `action pinned to "${ref}", not a 40-char commit SHA` : "action has no ref");
  });
}

// --- run -------------------------------------------------------------------
for (const file of walk(root)) {
  const name = file.split(sep).pop();
  const path = rel(file);
  if (/^(?:Dockerfile|Containerfile)(?:\..+)?$|\.(?:dockerfile|containerfile)$/iu.test(name)) checkDockerfile(file);
  else if (/^(?:docker-)?compose(?:\.[\w-]+)?\.ya?ml$/iu.test(name)) checkCompose(file);
  else if (name === "package.json") checkPackageJson(file);
  else if (/^\.github\/workflows\/[^/]+\.ya?ml$/u.test(path) || (path.startsWith(".github/") && /^action\.ya?ml$/u.test(name))) checkWorkflow(file);
}

const KIND_LABEL = {
  "docker-from": "Dockerfile FROM",
  "compose-image": "Compose image",
  "engines-node": "engines.node",
  "action-uses": "Action uses",
  "git-dependency": "Git dependency",
};

if (asJson) {
  process.stdout.write(`${JSON.stringify({ strict, count: findings.length, findings }, null, 2)}\n`);
} else {
  const escape = (s) => String(s).replace(/\|/gu, "\\|");
  const table = [
    `### pin-check: ${findings.length} floating reference${findings.length === 1 ? "" : "s"} (${strict ? "strict" : "report"} mode)`,
    "",
  ];
  if (findings.length === 0) {
    table.push("No floating references found.");
  } else {
    table.push("| Kind | File | Line | Reference | Issue |", "| --- | --- | --- | --- | --- |");
    for (const f of findings) {
      table.push(`| ${KIND_LABEL[f.kind]} | \`${escape(f.file)}\` | ${f.line} | \`${escape(f.ref)}\` | ${escape(f.detail)} |`);
    }
  }
  const markdown = `${table.join("\n")}\n`;
  if (process.env.GITHUB_ACTIONS === "true") {
    for (const f of findings) {
      const level = strict ? "error" : "warning";
      process.stdout.write(`::${level} file=${f.file},line=${f.line},title=pin-check (${KIND_LABEL[f.kind]})::${f.ref}: ${f.detail}\n`);
    }
  }
  if (process.env.GITHUB_STEP_SUMMARY && existsSync(process.env.GITHUB_STEP_SUMMARY)) {
    appendFileSync(process.env.GITHUB_STEP_SUMMARY, markdown);
  }
  process.stdout.write(markdown);
}

process.exitCode = strict && findings.length > 0 ? 1 : 0;
