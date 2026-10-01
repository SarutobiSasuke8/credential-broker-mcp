#!/usr/bin/env node
import { spawn } from "node:child_process";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { existsSync } from "node:fs";
import { copyFile, readFile, rename, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { z } from "zod";

import { scanForKeys } from "./import-scan.js";
import { MAX_SECRET_BYTES, platformSecretStore } from "./keychain.js";
import { renderKeysPage } from "./keys-page.js";
import { addCredentialToPolicy, describePolicyError, envVarFor } from "./policy-edit.js";
import { parseBrokerPolicy } from "./policy.js";

import type { IncomingMessage, ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import type { FoundKey } from "./import-scan.js";
import type { BrokerPolicy, CredentialSpec } from "./types.js";

/**
 * Key manager: a local web page for pasting API keys into the OS keychain
 * and adding APIs to the policy. Operator tool, never exposed to agents.
 *
 * - Listens on 127.0.0.1 only, with a random per-run token carried in the
 *   URL fragment (never sent in requests by the browser, never logged).
 * - Every API call needs that token, a JSON body, and a loopback Host
 *   header, which blocks other sites and DNS rebinding from driving it.
 * - Keys are write-only: the page can save, test, or remove a key, but no
 *   endpoint ever returns one.
 */

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const policyFile = resolve(process.env.BROKER_POLICY_FILE ?? join(packageRoot, "config", "broker.yaml"));
const auditFile = resolve(process.env.BROKER_AUDIT_FILE ?? join(packageRoot, "data", "audit.jsonl"));
const approvalsFile = resolve(process.env.BROKER_APPROVALS_FILE ?? join(packageRoot, "config", "approvals.json"));
const stdioEntry = join(packageRoot, "dist", "src", "stdio.js");
const requestedPort = Number(process.env.BROKER_KEYS_PORT ?? 0);
const IDLE_SHUTDOWN_MS = 30 * 60 * 1000;
const MAX_BODY_BYTES = 16 * 1024;

const store = platformSecretStore();
const token = randomBytes(32).toString("hex");
const nonce = randomBytes(16).toString("base64");

const ID = z.string().regex(/^[a-z0-9][a-z0-9._-]{1,63}$/u, "Use 2 to 64 lowercase letters, digits, dots, dashes or underscores.");
const QUERY_KEY = z.string().regex(/^[A-Za-z0-9._~-]{1,100}$/u);

const saveSecretSchema = z.object({ credentialId: ID, value: z.string() });
const credentialRefSchema = z.object({ credentialId: ID });
const testSchema = z.object({ credentialId: ID, path: z.string().max(500).default("") });
const addCredentialSchema = z.object({
  id: ID,
  description: z.string().max(200).default(""),
  kind: z.enum(["bearer", "header", "basic", "query"]),
  baseUrl: z.string().url(),
  paramName: z.string().regex(/^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,100}$/u).optional(),
  acknowledgeQueryRisk: z.boolean().default(false),
  value: z.string().default(""),
  grant: z
    .object({
      agentId: ID,
      displayName: z.string().max(100).optional(),
      queryParams: z.array(QUERY_KEY).max(50).default([]),
    })
    .nullable(),
});

// ---------------------------------------------------------------------------
// Policy and state
// ---------------------------------------------------------------------------

async function readPolicyText(): Promise<string | null> {
  return existsSync(policyFile) ? readFile(policyFile, "utf8") : null;
}

async function loadPolicy(): Promise<{ policy: BrokerPolicy | null; error: string | null; exists: boolean }> {
  const text = await readPolicyText();
  if (text === null) return { policy: null, error: null, exists: false };
  try {
    return { policy: parseBrokerPolicy(text), error: null, exists: true };
  } catch (error) {
    return { policy: null, error: describePolicyError(error), exists: true };
  }
}

/** Write via a temp file and keep one backup, so a crash never truncates the policy. */
async function writePolicy(text: string): Promise<void> {
  if (existsSync(policyFile)) await copyFile(policyFile, `${policyFile}.bak`);
  const temp = `${policyFile}.tmp-${process.pid}`;
  await writeFile(temp, text, { encoding: "utf8", mode: 0o600 });
  await rename(temp, policyFile);
}

function secretSource(credential: CredentialSpec, stored: Map<string, string>): "env" | "keychain" | "missing" {
  if (process.env[credential.envVar]) return "env";
  return stored.has(credential.id) ? "keychain" : "missing";
}

async function buildState(): Promise<object> {
  const { policy, error, exists } = await loadPolicy();
  const stored = new Map((store ? await store.list() : []).map((k) => [k.id, k.comment]));
  const credentials = policy
    ? [...policy.credentials.values()].map((c) => ({
        id: c.id,
        description: c.description,
        kind: c.kind,
        paramName: c.paramName ?? null,
        baseUrl: c.baseUrl,
        envVar: c.envVar,
        source: secretSource(c, stored),
        note: stored.get(c.id) ?? "",
        grantedTo: [...policy.agents.values()].filter((a) => a.grants.has(c.id)).map((a) => a.id),
      }))
    : [];
  const agents = policy ? [...policy.agents.values()].map((a) => ({ id: a.id, displayName: a.displayName, enabled: a.enabled })) : [];
  return {
    policyFile,
    policyExists: exists,
    policyError: error,
    keychain: store ? "Windows Credential Manager" : null,
    maxSecretBytes: MAX_SECRET_BYTES,
    credentials,
    // Keys housed in the keychain that no API in the policy uses yet.
    storedOnly: [...stored]
      .filter(([id]) => !policy?.credentials.has(id))
      .map(([id, note]) => ({ id, note }))
      .sort((a, b) => a.id.localeCompare(b.id)),
    agents,
    register: {
      stdioEntry,
      policyFile,
      auditFile,
      approvalsFile,
    },
  };
}

/** Pasted keys often carry a trailing newline or a copied "Bearer " prefix. */
function cleanSecret(raw: string): string {
  return raw.trim().replace(/^bearer\s+/iu, "");
}

async function credentialById(id: string): Promise<CredentialSpec> {
  const { policy, error } = await loadPolicy();
  if (!policy) throw new HttpError(409, error ?? "No policy file yet. Add an API first.");
  const credential = policy.credentials.get(id);
  if (!credential) throw new HttpError(404, `No credential named '${id}' in the policy.`);
  return credential;
}

function requireStore(): NonNullable<typeof store> {
  if (!store) {
    throw new HttpError(
      501,
      "No supported keychain on this platform (or BROKER_KEYCHAIN=off). Set the credential's env_var instead.",
    );
  }
  return store;
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

class HttpError extends Error {
  public constructor(public readonly status: number, message: string) {
    super(message);
  }
}

async function saveSecret(body: unknown): Promise<object> {
  // Ids outside the policy are allowed: those keys are housed, not yet usable.
  const input = saveSecretSchema.parse(body);
  const value = cleanSecret(input.value);
  if (!value) throw new HttpError(400, "Paste a key first.");
  await requireStore().set(input.credentialId, value);
  return { ok: true };
}

async function deleteSecret(body: unknown): Promise<object> {
  const input = credentialRefSchema.parse(body);
  const removed = await requireStore().delete(input.credentialId);
  return { ok: true, removed };
}

async function addCredential(body: unknown): Promise<object> {
  const input = addCredentialSchema.parse(body);
  if ((input.kind === "header" || input.kind === "query") && !input.paramName) {
    throw new HttpError(400, input.kind === "header" ? "Enter the header name, e.g. x-api-key." : "Enter the query parameter name, e.g. api_key.");
  }
  if (input.kind === "query" && !input.acknowledgeQueryRisk) {
    throw new HttpError(400, "Tick the box acknowledging that query-string keys can end up in server logs.");
  }
  const value = cleanSecret(input.value);
  if (value && !store) requireStore();

  let text: string;
  try {
    text = addCredentialToPolicy(await readPolicyText(), {
      id: input.id,
      description: input.description,
      kind: input.kind,
      baseUrl: input.baseUrl.replace(/\/+$/u, ""),
      ...(input.paramName ? { paramName: input.paramName } : {}),
      grant: input.grant
        ? {
            agentId: input.grant.agentId,
            ...(input.grant.displayName ? { displayName: input.grant.displayName } : {}),
            queryParams: input.grant.queryParams,
          }
        : null,
    });
  } catch (error) {
    throw new HttpError(400, error instanceof Error ? error.message : String(error));
  }
  // Store the key before touching the policy: a failed keychain write
  // leaves nothing half-done.
  if (value) await requireStore().set(input.id, value);
  await writePolicy(text);
  return { ok: true, envVar: envVarFor(input.id) };
}

type Probeable = Pick<CredentialSpec, "baseUrl" | "origin" | "kind" | "paramName">;

/**
 * One GET with the key injected, returning only the status code. Lets the
 * operator confirm a key works before handing it to an agent.
 */
async function probe(credential: Probeable, secret: string, rawPath: string): Promise<{ ok: boolean; status: number; statusText: string }> {
  const path = rawPath.trim();
  if (path && !path.startsWith("/")) throw new HttpError(400, "Test path must start with '/'.");
  const url = new URL(`${credential.baseUrl}${path}`);
  if (url.origin !== credential.origin) throw new HttpError(400, "Test path must stay on the API's own host.");

  const headers = new Headers({ accept: "application/json, */*;q=0.5", "user-agent": "credential-broker-keys" });
  switch (credential.kind) {
    case "bearer":
      headers.set("authorization", `Bearer ${secret}`);
      break;
    case "header":
      headers.set(credential.paramName ?? "x-api-key", secret);
      break;
    case "basic":
      headers.set("authorization", `Basic ${Buffer.from(secret, "utf8").toString("base64")}`);
      break;
    case "query":
      url.searchParams.set(credential.paramName ?? "api_key", secret);
      break;
  }
  try {
    const response = await fetch(url, { method: "GET", headers, redirect: "manual", signal: AbortSignal.timeout(10_000) });
    await response.body?.cancel();
    return { ok: true, status: response.status, statusText: response.statusText };
  } catch {
    // The fetch error can quote the URL, and a query key lives in the URL.
    return { ok: false, status: 0, statusText: "Could not reach the API (network error or timeout)." };
  }
}

async function testCredential(body: unknown): Promise<object> {
  const input = testSchema.parse(body);
  const credential = await credentialById(input.credentialId);
  const secret = process.env[credential.envVar] ?? (await requireStore().getMany([credential.id])).get(credential.id);
  if (!secret) throw new HttpError(409, "No key saved for this API yet.");
  return probe(credential, secret, input.path);
}

// ---------------------------------------------------------------------------
// Import of keys already on this machine
// ---------------------------------------------------------------------------

// Values from the last scan, keyed by row id. Held in this process only.
let lastScan = new Map<string, FoundKey>();

async function scanImport(): Promise<object> {
  const found = await scanForKeys();
  lastScan = new Map(found.map((row) => [row.rowId, row]));
  const stored = store ? await store.list() : [];
  const storedValues = store ? await store.getMany(stored.map((k) => k.id)) : new Map<string, string>();
  const { policy } = await loadPolicy();
  return {
    rows: found.map((row) => {
      const alreadyStoredAs = [...storedValues].find(([, value]) => value === row.value)?.[0] ?? null;
      return {
        rowId: row.rowId,
        name: row.name,
        suggestedId: row.suggestedId,
        preset: row.preset,
        sources: row.sources,
        alreadyStoredAs,
        idTaken: policy?.credentials.has(row.suggestedId) === true || stored.some((k) => k.id === row.suggestedId),
        sensitive: row.sensitive,
      };
    }),
  };
}

const applyImportSchema = z.object({
  agentId: ID.nullable(),
  agentDisplayName: z.string().max(100).optional(),
  items: z
    .array(z.object({ rowId: z.string().regex(/^[0-9a-f]{16}$/u), id: ID, mode: z.enum(["api", "store"]) }))
    .min(1)
    .max(100),
});

function sourceNote(row: FoundKey): string {
  const first = row.sources[0];
  const where = first ? `${first.where}${first.path ? ` ${first.path}` : ""}` : "unknown";
  const more = row.sources.length > 1 ? ` (+${row.sources.length - 1} more)` : "";
  return `Imported from ${row.name}: ${where}${more}`;
}

/**
 * Store each picked key, and for "api" rows also add the credential and a
 * read grant. Rows are independent: one failure is reported and the rest
 * carry on. The policy is written once, after every edit has validated.
 */
async function applyImport(body: unknown): Promise<object> {
  const input = applyImportSchema.parse(body);
  const keychain = requireStore();
  let text = await readPolicyText();
  let policyChanged = false;
  const results: { rowId: string; id: string; ok: boolean; message: string; testPath?: string }[] = [];

  for (const item of input.items) {
    const row = lastScan.get(item.rowId);
    if (!row) {
      results.push({ rowId: item.rowId, id: item.id, ok: false, message: "Scan again: this row is out of date." });
      continue;
    }
    if (Buffer.byteLength(row.value, "utf8") > MAX_SECRET_BYTES) {
      results.push({ rowId: item.rowId, id: item.id, ok: false, message: `Too long for Credential Manager (over ${MAX_SECRET_BYTES} bytes).` });
      continue;
    }
    let nextText = text;
    if (item.mode === "api") {
      if (!row.preset) {
        results.push({ rowId: item.rowId, id: item.id, ok: false, message: "No known API for this key. Store it, then connect it with Add an API." });
        continue;
      }
      try {
        nextText = addCredentialToPolicy(text, {
          id: item.id,
          description: row.preset.label,
          kind: row.preset.kind,
          baseUrl: row.preset.baseUrl,
          ...(row.preset.paramName ? { paramName: row.preset.paramName } : {}),
          grant: input.agentId
            ? {
                agentId: input.agentId,
                ...(input.agentDisplayName ? { displayName: input.agentDisplayName } : {}),
                queryParams: [],
              }
            : null,
        });
      } catch (error) {
        results.push({ rowId: item.rowId, id: item.id, ok: false, message: error instanceof Error ? error.message : String(error) });
        continue;
      }
    }
    try {
      await keychain.set(item.id, row.value, sourceNote(row));
    } catch (error) {
      results.push({ rowId: item.rowId, id: item.id, ok: false, message: error instanceof Error ? error.message : String(error) });
      continue;
    }
    if (nextText !== text) {
      text = nextText;
      policyChanged = true;
    }
    results.push({
      rowId: item.rowId,
      id: item.id,
      ok: true,
      message: item.mode === "api" ? `Saved and added as an API.` : "Saved (stored only).",
      ...(item.mode === "api" && row.preset?.testPath ? { testPath: row.preset.testPath } : {}),
    });
  }

  if (policyChanged && text !== null) await writePolicy(text);

  // Prove each new API key works, now that the policy is on disk.
  if (policyChanged && text !== null) {
    const policy = parseBrokerPolicy(text);
    await Promise.all(
      results.map(async (result) => {
        if (!result.ok || !result.testPath) return;
        const credential = policy.credentials.get(result.id);
        const value = lastScan.get(result.rowId)?.value;
        if (!credential || !value) return;
        const outcome = await probe(credential, value, result.testPath);
        Object.assign(result, { test: { path: result.testPath, status: outcome.status } });
      }),
    );
  }
  return { results };
}

// ---------------------------------------------------------------------------
// HTTP plumbing
// ---------------------------------------------------------------------------

function send(res: ServerResponse, status: number, contentType: string, payload: string): void {
  res.writeHead(status, {
    "content-type": contentType,
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "content-security-policy": `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`,
  });
  res.end(payload);
}

function sendJson(res: ServerResponse, status: number, value: unknown): void {
  send(res, status, "application/json; charset=utf-8", JSON.stringify(value));
}

function readJsonBody(req: IncomingMessage): Promise<unknown> {
  return new Promise((resolveBody, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(new HttpError(413, "Request too large."));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      try {
        resolveBody(chunks.length ? JSON.parse(Buffer.concat(chunks).toString("utf8")) : {});
      } catch {
        reject(new HttpError(400, "Body must be JSON."));
      }
    });
    req.on("error", reject);
  });
}

function tokenMatches(header: string | undefined): boolean {
  const presented = Buffer.from(header?.replace(/^Bearer /u, "") ?? "", "utf8");
  const expected = Buffer.from(token, "utf8");
  return presented.length === expected.length && timingSafeEqual(presented, expected);
}

let idleTimer: NodeJS.Timeout | undefined;
function touch(): void {
  if (idleTimer) clearTimeout(idleTimer);
  idleTimer = setTimeout(() => {
    console.log("Key manager closed after 30 minutes idle.");
    process.exit(0);
  }, IDLE_SHUTDOWN_MS);
  idleTimer.unref();
}

const routes: Record<string, (body: unknown) => Promise<object>> = {
  "POST /api/secret": saveSecret,
  "POST /api/secret/delete": deleteSecret,
  "POST /api/credential": addCredential,
  "POST /api/test": testCredential,
  "POST /api/state": () => buildState(),
  "POST /api/import/scan": scanImport,
  "POST /api/import/apply": applyImport,
};

const server = createServer((req, res) => {
  void (async () => {
    touch();
    const { port } = server.address() as AddressInfo;
    if (req.headers.host !== `127.0.0.1:${port}` && req.headers.host !== `localhost:${port}`) {
      send(res, 421, "text/plain", "Wrong host.");
      return;
    }
    const path = (req.url ?? "/").split("?")[0];

    if (req.method === "GET" && path === "/") {
      send(res, 200, "text/html; charset=utf-8", renderKeysPage(nonce));
      return;
    }
    if (req.method === "POST" && path === "/api/close") {
      if (!tokenMatches(req.headers.authorization)) {
        sendJson(res, 401, { error: "This page has expired. Run npm run keys again." });
        return;
      }
      sendJson(res, 200, { ok: true });
      setTimeout(() => process.exit(0), 100);
      return;
    }

    const handler = routes[`${req.method ?? ""} ${path}`];
    if (!handler) {
      send(res, 404, "text/plain", "Not found.");
      return;
    }
    if (!tokenMatches(req.headers.authorization)) {
      sendJson(res, 401, { error: "This page has expired. Run npm run keys again." });
      return;
    }
    if (!req.headers["content-type"]?.startsWith("application/json")) {
      sendJson(res, 415, { error: "JSON only." });
      return;
    }
    try {
      sendJson(res, 200, await handler(await readJsonBody(req)));
    } catch (error) {
      if (error instanceof HttpError) sendJson(res, error.status, { error: error.message });
      else if (error instanceof z.ZodError) sendJson(res, 400, { error: describePolicyError(error) });
      else sendJson(res, 500, { error: error instanceof Error ? error.message : "Unexpected error." });
    }
  })();
});

function openBrowser(url: string): void {
  // Token is hex and the URL has no shell metacharacters, but avoid a shell
  // anyway: rundll32 hands the URL straight to the default browser.
  const [command, args] =
    process.platform === "win32"
      ? ["rundll32", ["url.dll,FileProtocolHandler", url]]
      : process.platform === "darwin"
        ? ["open", [url]]
        : ["xdg-open", [url]];
  spawn(command, args, { detached: true, stdio: "ignore" }).on("error", () => undefined).unref();
}

server.on("error", (error: NodeJS.ErrnoException) => {
  console.error(
    error.code === "EADDRINUSE"
      ? `Port ${requestedPort} is in use. Is the key manager already open? Unset BROKER_KEYS_PORT to pick a free port.`
      : `Key manager could not start: ${error.message}`,
  );
  process.exit(1);
});

server.listen(requestedPort, "127.0.0.1", () => {
  const { port } = server.address() as AddressInfo;
  const url = `http://127.0.0.1:${port}/#${token}`;
  console.log("Credential Broker key manager");
  console.log(`Policy: ${policyFile}`);
  console.log(`Keys:   ${store ? "Windows Credential Manager" : "no keychain on this platform; use env vars"}`);
  console.log(`\nOpen:   ${url}\n`);
  console.log("Press Ctrl+C to stop. Closes itself after 30 minutes idle.");
  touch();
  if (!process.argv.includes("--no-open")) openBrowser(url);
});
