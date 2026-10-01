import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { basename, dirname, join } from "node:path";

import type { CredentialKind } from "./types.js";

/**
 * Finds API keys the operator already has scattered around the machine, so
 * the key manager can move them into the keychain in one pass.
 *
 * Values stay in this process. Callers get names, locations, and a row id;
 * the import endpoint looks the value up by row id server-side, so a key
 * never travels to the browser.
 *
 * Read-only: nothing here edits or deletes the original copies.
 */

export interface Preset {
  /** Suggested credential id. */
  id: string;
  label: string;
  baseUrl: string;
  kind: CredentialKind;
  paramName?: string;
  /** Cheap authenticated GET that proves the key works, when the API has one. */
  testPath?: string;
}

export interface KeySource {
  /** Where it was found, for display. */
  where: string;
  path: string;
  /** Short label used to tell apart different keys with the same name. */
  tag: string;
}

export interface FoundKey {
  rowId: string;
  name: string;
  suggestedId: string;
  preset: Preset | null;
  sources: KeySource[];
  /** Wallet keys and seed phrases: house them, never wire them to an API. */
  sensitive: boolean;
  /** Kept server-side only; stripped before anything is sent to the page. */
  value: string;
}

// Names that look like secrets. Public-by-design values (browser-exposed
// build variables, publishable keys) and short-lived deploy tokens are left
// out: housing them adds clutter, not safety.
const SECRET_NAME = /(api_?key|_key$|token|secret|password|_hash$|webhook_url|^authorization$)/iu;
const WALLET_SECRET = /(private_?key|mnemonic|seed_?phrase|wallet_?secret)/iu;
const NOT_SECRET = /^(next_public_|expo_public_|public_|vite_)|publishable|oidc/iu;

const PRESETS: { match: RegExp; preset: Preset }[] = [
  {
    match: /^OPENROUTER_API_KEY$/u,
    preset: { id: "openrouter", label: "OpenRouter", baseUrl: "https://openrouter.ai/api/v1", kind: "bearer", testPath: "/key" },
  },
  {
    match: /^(GEMINI_API_KEY|GOOGLE_GENERATIVE_AI_API_KEY|GOOGLE_API_KEY)$/u,
    preset: {
      id: "gemini",
      label: "Google Gemini",
      baseUrl: "https://generativelanguage.googleapis.com/v1beta",
      kind: "header",
      paramName: "x-goog-api-key",
      testPath: "/models",
    },
  },
  {
    match: /^ELEVENLABS_API_KEY$/u,
    preset: { id: "elevenlabs", label: "ElevenLabs", baseUrl: "https://api.elevenlabs.io/v1", kind: "header", paramName: "xi-api-key", testPath: "/user" },
  },
  {
    match: /^(DIGITALOCEAN_ACCESS_TOKEN|DIGITALOCEAN_TOKEN|DO_TOKEN)$/u,
    preset: { id: "digitalocean", label: "DigitalOcean", baseUrl: "https://api.digitalocean.com/v2", kind: "bearer", testPath: "/account" },
  },
  {
    match: /^NANSEN_API_KEY$/u,
    preset: { id: "nansen", label: "Nansen", baseUrl: "https://api.nansen.ai/api/v1", kind: "header", paramName: "apiKey" },
  },
  {
    match: /^TYPESAFE_API_KEY$/u,
    preset: { id: "typesafe", label: "TypeSafe", baseUrl: "https://api.typesafe.ai", kind: "bearer" },
  },
  {
    match: /^CLERK_SECRET_KEY$/u,
    preset: { id: "clerk", label: "Clerk", baseUrl: "https://api.clerk.com/v1", kind: "bearer", testPath: "/users?limit=1" },
  },
  {
    match: /^COINGECKO_API_KEY$/u,
    preset: {
      id: "coingecko",
      label: "CoinGecko (demo key)",
      baseUrl: "https://api.coingecko.com/api/v3",
      kind: "header",
      paramName: "x-cg-demo-api-key",
      testPath: "/ping",
    },
  },
  {
    match: /^(OPENAI_API_KEY)$/u,
    preset: { id: "openai", label: "OpenAI", baseUrl: "https://api.openai.com/v1", kind: "bearer", testPath: "/models" },
  },
  {
    match: /^(ANTHROPIC_API_KEY)$/u,
    preset: {
      id: "anthropic",
      label: "Anthropic",
      baseUrl: "https://api.anthropic.com/v1",
      kind: "header",
      paramName: "x-api-key",
      testPath: "/models",
    },
  },
  {
    match: /^(GITHUB_TOKEN|GH_TOKEN|GITHUB_PAT)$/u,
    preset: { id: "github", label: "GitHub", baseUrl: "https://api.github.com", kind: "bearer", testPath: "/user" },
  },
];

/** MCP servers whose header keys map to a known API. Keyed by URL host. */
const MCP_HEADER_PRESETS: Record<string, Preset> = {
  "api.pixellab.ai": { id: "pixellab", label: "PixelLab", baseUrl: "https://api.pixellab.ai", kind: "bearer" },
};

const SKIP_DIRS = new Set([
  "node_modules", ".git", "dist", "build", ".next", ".turbo", ".venv", "venv", "__pycache__", ".obsidian", ".cache", "coverage",
]);

function rowIdFor(name: string, value: string): string {
  // Same name and value found in several places is one row.
  return createHash("sha256").update(`${name}\u0000${value}`).digest("hex").slice(0, 16);
}

function idFromName(name: string): string {
  const id = name.toLowerCase().replace(/_/gu, "-").replace(/[^a-z0-9.-]/gu, "").replace(/^-+|-+$/gu, "");
  return id.length >= 2 ? id.slice(0, 64) : `key-${id}`;
}

function presetFor(name: string): Preset | null {
  return PRESETS.find((p) => p.match.test(name))?.preset ?? null;
}

/** Minimal dotenv parsing: KEY=value, optional export, quotes, trailing comments. */
export function parseDotenv(text: string): Map<string, string> {
  const result = new Map<string, string>();
  for (const line of text.split(/\r?\n/u)) {
    const match = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/u.exec(line);
    if (!match?.[1]) continue;
    let value = match[2] ?? "";
    const quote = value[0];
    if ((quote === '"' || quote === "'") && value.indexOf(quote, 1) > 0) {
      value = value.slice(1, value.indexOf(quote, 1));
    } else {
      value = value.replace(/\s+#.*$/u, "").trim();
    }
    if (value) result.set(match[1], value);
  }
  return result;
}

async function findDotenvFiles(root: string, depth: number, found: string[]): Promise<void> {
  if (depth < 0) return;
  let entries;
  try {
    entries = await readdir(root, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    const path = join(root, entry.name);
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name)) await findDotenvFiles(path, depth - 1, found);
    } else if (/^\.env(\..+)?$/u.test(entry.name) && !/example|sample|template|defaults/iu.test(entry.name)) {
      found.push(path);
    }
  }
}

function shortPath(path: string): string {
  const home = homedir();
  return path.startsWith(home) ? `~${path.slice(home.length)}` : path;
}

function readUserEnvironment(): Promise<Record<string, string>> {
  if (process.platform !== "win32") return Promise.resolve({});
  // User-level variables only (HKCU\Environment), not whatever the current
  // process inherited.
  const script =
    "$o=@{}; $e=[Environment]::GetEnvironmentVariables('User'); foreach($k in $e.Keys){$o[$k]=[string]$e[$k]}; " +
    "[Console]::Out.Write(($o | ConvertTo-Json -Compress))";
  return new Promise((resolve) => {
    execFile(
      "powershell.exe",
      ["-NoProfile", "-NonInteractive", "-Command", script],
      { windowsHide: true, maxBuffer: 4 * 1024 * 1024, timeout: 20_000 },
      (error, stdout) => {
        if (error) {
          resolve({});
          return;
        }
        try {
          resolve(JSON.parse(stdout || "{}") as Record<string, string>);
        } catch {
          resolve({});
        }
      },
    );
  });
}

interface McpServerConfig {
  url?: string;
  env?: Record<string, unknown>;
  headers?: Record<string, unknown>;
}

function mcpServersIn(config: unknown): { scope: string; name: string; server: McpServerConfig }[] {
  const out: { scope: string; name: string; server: McpServerConfig }[] = [];
  if (!config || typeof config !== "object") return out;
  const root = config as { mcpServers?: Record<string, McpServerConfig>; projects?: Record<string, { mcpServers?: Record<string, McpServerConfig> }> };
  for (const [name, server] of Object.entries(root.mcpServers ?? {})) out.push({ scope: "", name, server });
  for (const [project, value] of Object.entries(root.projects ?? {})) {
    for (const [name, server] of Object.entries(value.mcpServers ?? {})) out.push({ scope: basename(project), name, server });
  }
  return out;
}

export interface ScanOptions {
  /** Folders searched for .env files. */
  roots: string[];
  /** MCP client config files (Claude Code, Claude Desktop, Cursor). */
  mcpConfigs: string[];
  /** Windows user-level environment variables. Tests pass a fixed map. */
  userEnvironment?: () => Promise<Record<string, string>>;
}

export function defaultScanOptions(env: Record<string, string | undefined> = process.env): ScanOptions {
  const home = homedir();
  const roots = env.BROKER_IMPORT_ROOTS
    ? env.BROKER_IMPORT_ROOTS.split(";").filter(Boolean)
    : [join(home, "Documents"), "C:/Dev"];
  return {
    roots,
    mcpConfigs: [
      join(home, ".claude.json"),
      join(env.APPDATA ?? join(home, "AppData", "Roaming"), "Claude", "claude_desktop_config.json"),
      join(home, ".cursor", "mcp.json"),
    ],
  };
}

export async function scanForKeys(options: ScanOptions = defaultScanOptions()): Promise<FoundKey[]> {
  const rows = new Map<string, FoundKey>();
  const add = (name: string, value: string, source: KeySource, preset: Preset | null = presetFor(name)): void => {
    const trimmed = value.trim();
    if (!trimmed) return;
    const rowId = rowIdFor(preset?.id ?? name, trimmed);
    const existing = rows.get(rowId);
    if (existing) {
      if (!existing.sources.some((s) => s.where === source.where && s.path === source.path)) existing.sources.push(source);
      return;
    }
    const sensitive = WALLET_SECRET.test(name);
    rows.set(rowId, {
      rowId,
      name,
      suggestedId: preset?.id ?? idFromName(name),
      preset: sensitive ? null : preset,
      sources: [source],
      sensitive,
      value: trimmed,
    });
  };
  const isSecretName = (name: string): boolean => SECRET_NAME.test(name) && !NOT_SECRET.test(name);

  for (const [name, value] of Object.entries(await (options.userEnvironment ?? readUserEnvironment)())) {
    if (isSecretName(name)) add(name, value, { where: "Windows user environment variable", path: "", tag: "user-env" });
  }

  for (const file of options.mcpConfigs) {
    let config: unknown;
    try {
      config = JSON.parse(await readFile(file, "utf8"));
    } catch {
      continue;
    }
    for (const { scope, name, server } of mcpServersIn(config)) {
      const where = `MCP server '${name}'${scope ? ` (${scope})` : ""}`;
      for (const [key, value] of Object.entries(server.env ?? {})) {
        if (typeof value === "string" && isSecretName(key)) add(key, value, { where: `${where} env`, path: shortPath(file), tag: scope || name });
      }
      let host = "";
      try {
        host = server.url ? new URL(server.url).host : "";
      } catch {
        host = "";
      }
      for (const [header, value] of Object.entries(server.headers ?? {})) {
        if (typeof value !== "string" || !isSecretName(header)) continue;
        const preset = MCP_HEADER_PRESETS[host] ?? null;
        const clean = header.toLowerCase() === "authorization" ? value.replace(/^bearer\s+/iu, "") : value;
        add(preset ? preset.id.toUpperCase() : `${name}_${header}`.toUpperCase().replace(/[^A-Z0-9]/gu, "_"), clean, { where: `${where} header`, path: shortPath(file), tag: scope || "global" }, preset);
      }
    }
  }

  const dotenvFiles: string[] = [];
  for (const root of options.roots) await findDotenvFiles(root, 5, dotenvFiles);
  for (const file of dotenvFiles) {
    let text: string;
    try {
      text = await readFile(file, "utf8");
    } catch {
      continue;
    }
    for (const [name, value] of parseDotenv(text)) {
      if (isSecretName(name)) add(name, value, { where: ".env file", path: shortPath(file), tag: basename(dirname(file)) });
    }
  }

  // Different values under the same suggested id (three different Gemini
  // keys in three projects) get the project folder as a suffix.
  const byId = new Map<string, FoundKey[]>();
  for (const row of rows.values()) byId.set(row.suggestedId, [...(byId.get(row.suggestedId) ?? []), row]);
  for (const [id, group] of byId) {
    if (group.length < 2) continue;
    const taken = new Set<string>();
    group.forEach((row, index) => {
      const tag = idFromName(row.sources[0]?.tag ?? "");
      let candidate = tag && !tag.startsWith("key-") ? `${id}-${tag}`.slice(0, 64) : `${id}-${index + 1}`;
      if (taken.has(candidate)) candidate = `${candidate.slice(0, 60)}-${index + 1}`;
      taken.add(candidate);
      row.suggestedId = candidate;
    });
  }

  return [...rows.values()].sort((a, b) => Number(b.preset !== null) - Number(a.preset !== null) || a.suggestedId.localeCompare(b.suggestedId));
}
