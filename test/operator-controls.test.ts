import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { approvalState, createApproval, parseApprovals, pruneApprovals, revokeApproval } from "../src/approvals-admin.js";
import { MemoryAuditSink } from "../src/audit.js";
import { BrokerEngine, MapSecretProvider } from "../src/engine.js";
import { applyMetaUpdate, EMPTY_META, markRotated } from "../src/key-meta.js";
import { anyPauseActive, applyPause, checkPause, EMPTY_PAUSE, FilePauseGuard, parsePauseState, serializePauseState } from "../src/kill-switch.js";
import { parseBrokerPolicy } from "../src/policy.js";
import { ReloadWatcher, reloadMarkerPath, touchReloadMarker } from "../src/reload.js";
import { summarizeUsage } from "../src/usage.js";
import { findPresetByOrigin, listPresets } from "../src/import-scan.js";

const NOW = new Date("2026-11-06T12:00:00Z");

const POLICY = `
version: 2
credentials:
  - id: api
    description: Test API
    kind: bearer
    env_var: T_API
    base_url: https://api.example.com/v1
  - id: other
    description: Other API
    kind: bearer
    env_var: T_OTHER
    base_url: https://other.example.com
agents:
  - id: claude
    grants:
      - credential: api
        operations:
          - id: read-all
            method: GET
            path: /**
      - credential: other
        operations:
          - id: read-all
            method: GET
            path: /**
  - id: codex
    grants:
      - credential: api
        operations:
          - id: read-all
            method: GET
            path: /**
`;

async function withTempDir<T>(run: (dir: string) => Promise<T>): Promise<T> {
  const dir = await mkdtemp(join(tmpdir(), "broker-test-"));
  try {
    return await run(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

// ---- pause switch --------------------------------------------------------

void test("pause scopes: everything beats an agent, an agent beats a credential, and resuming clears only that scope", () => {
  let state = applyPause(EMPTY_PAUSE, { kind: "credential", id: "api" }, true, "key leaked", NOW);
  assert.deepEqual(checkPause(state, "claude", "api"), { paused: true, scope: "credential", reason: "key leaked" });
  assert.deepEqual(checkPause(state, "claude", "other"), { paused: false });

  state = applyPause(state, { kind: "agent", id: "claude" }, true, "", NOW);
  assert.equal(checkPause(state, "claude", "other").paused, true);
  assert.equal(checkPause(state, "codex", "other").paused, false);

  state = applyPause(state, { kind: "all" }, true, "stop", NOW);
  assert.equal(checkPause(state, "codex", "other").paused, true);
  assert.ok(anyPauseActive(state));

  state = applyPause(state, { kind: "all" }, false, "", NOW);
  assert.equal(checkPause(state, "codex", "other").paused, false);
  assert.equal(checkPause(state, "claude", "other").paused, true, "agent pause survives resuming all");
});

void test("pause state round-trips and rejects anything it does not understand", () => {
  const state = applyPause(EMPTY_PAUSE, { kind: "all" }, true, "test", NOW);
  const parsed = parsePauseState(serializePauseState(state));
  assert.ok(parsed.ok);
  assert.deepEqual(parsed.ok && parsed.state, state);
  assert.equal(parsePauseState("{ nope").ok, false);
  assert.equal(parsePauseState(JSON.stringify({ version: 2 })).ok, false);
});

void test("the pause guard fails closed: missing file is open, an unreadable or invalid file pauses everything", async () => {
  await withTempDir(async (dir) => {
    const file = join(dir, "pause.json");
    const guard = new FilePauseGuard(file);
    assert.deepEqual(await guard.check("claude", "api"), { paused: false });

    await writeFile(file, "{ half written");
    const broken = await guard.check("claude", "api");
    assert.equal(broken.paused && broken.scope, "unreadable");

    await writeFile(file, serializePauseState(applyPause(EMPTY_PAUSE, { kind: "agent", id: "codex" }, true, "", NOW)));
    assert.deepEqual(await guard.check("claude", "api"), { paused: false });
    assert.equal((await guard.check("codex", "api")).paused, true);
  });
});

void test("a paused engine denies before any upstream call, audits only the scope, and never relays the reason", async () => {
  let upstreamCalls = 0;
  const audit = new MemoryAuditSink();
  const paused = { value: false };
  const engine = new BrokerEngine({
    policy: parseBrokerPolicy(POLICY),
    principalId: "claude",
    secrets: new MapSecretProvider(new Map([["api", "secret-value-123456"]])),
    audit,
    pause: {
      check: () => Promise.resolve(paused.value ? { paused: true as const, scope: "all" as const, reason: "operator typed: key leaked on pastebin" } : { paused: false as const }),
    },
    fetchImpl: () => {
      upstreamCalls += 1;
      return Promise.resolve(new Response("{}", { status: 200, headers: { "content-type": "application/json" } }));
    },
  });

  const open = await engine.execute({ credentialId: "api", method: "GET", url: "https://api.example.com/v1/things" });
  assert.equal(open.kind, "success");
  assert.equal(upstreamCalls, 1);

  paused.value = true;
  const blocked = await engine.execute({ credentialId: "api", method: "GET", url: "https://api.example.com/v1/things" });
  assert.equal(blocked.kind, "denied");
  assert.equal(upstreamCalls, 1, "nothing may reach the upstream while paused");
  assert.equal(blocked.kind === "denied" && blocked.decidingRule?.source, "operator-pause");
  const everything = JSON.stringify([blocked, audit.records]);
  assert.doesNotMatch(everything, /pastebin/u, "the operator's typed reason stays private");
  assert.ok(audit.records.some((r) => r.outcome === "denied" && r.detail === "paused by operator (all)"));

  const explained = await engine.explain({ credentialId: "api", method: "GET", url: "https://api.example.com/v1/things" });
  assert.equal(explained.allowed, false);
  assert.equal(explained.decidingRule?.source, "operator-pause");
});

// ---- hot reload ----------------------------------------------------------

void test("reload watcher: no change means no reload, a changed marker reloads once, a failure keeps the old state", async () => {
  await withTempDir(async (dir) => {
    const marker = join(dir, ".broker-reload");
    let loads = 0;
    let failNext = false;
    const failures: string[] = [];
    const watcher = new ReloadWatcher<number>({
      markerFile: marker,
      load: () => {
        loads += 1;
        if (failNext) return Promise.reject(new Error("policy is invalid"));
        return Promise.resolve(loads);
      },
      onFailure: (message) => {
        failures.push(message);
      },
    });
    await watcher.init();
    assert.equal(await watcher.refresh(), null);
    assert.equal(loads, 0);

    await touchReloadMarker(marker);
    assert.equal(await watcher.refresh(), 1);
    assert.equal(await watcher.refresh(), null, "the same marker does not reload twice");

    failNext = true;
    await touchReloadMarker(marker);
    assert.equal(await watcher.refresh(), null);
    assert.deepEqual(failures, ["policy is invalid"]);
    assert.equal(await watcher.refresh(), null, "a failed marker is not retried in a loop");

    failNext = false;
    await touchReloadMarker(marker);
    assert.equal(await watcher.refresh(), 3, "loads so far: first reload, the failed one, then this one");
  });
});

void test("the reload marker sits beside the policy unless overridden", () => {
  assert.match(reloadMarkerPath(join("a", "b", "broker.yaml"), undefined), /b[\\/]\.broker-reload$/u);
  assert.match(reloadMarkerPath("ignored", join("x", "marker")), /x[\\/]marker$/u);
});

// ---- usage ---------------------------------------------------------------

void test("usage counts finished requests in the window, finds the last user, and ignores non-request records", () => {
  const lines = [
    { at: "2026-11-06T10:00:00Z", agentId: "claude", credentialId: "itch", method: "GET", outcome: "requested" },
    { at: "2026-11-06T10:00:01Z", agentId: "claude", credentialId: "itch", method: "GET", outcome: "succeeded" },
    { at: "2026-11-05T09:00:00Z", agentId: "codex", credentialId: "itch", method: "GET", outcome: "denied" },
    { at: "2026-11-04T09:00:00Z", agentId: "codex", credentialId: "itch", method: "GET", outcome: "failed" },
    { at: "2026-09-01T09:00:00Z", agentId: "codex", credentialId: "itch", method: "GET", outcome: "succeeded" },
    { at: "2026-11-06T11:00:00Z", agentId: "claude", credentialId: "itch", method: "REQUEST_KEY", outcome: "requested" },
    { at: "2026-11-06T11:30:00Z", agentId: "claude", credentialId: "-", method: "RELOAD", outcome: "requested" },
  ].map((row) => JSON.stringify(row));
  lines.push("not json", "");
  const usage = summarizeUsage(lines, NOW).get("itch");
  assert.deepEqual(usage, { lastAt: "2026-11-06T10:00:01Z", lastAgent: "claude", succeeded: 1, denied: 1, failed: 1 });
  assert.equal(summarizeUsage(lines, NOW).has("-"), false);
});

// ---- approvals -----------------------------------------------------------

void test("approvals: create within limits, expire, revoke, prune, and keep unknown fields", () => {
  assert.throws(() => createApproval([], { agentId: "claude", credentialId: "api", operationId: "x", minutes: 0 }, NOW), /lifetime/u);
  assert.throws(() => createApproval([], { agentId: "claude", credentialId: "api", operationId: "x", minutes: 24 * 60 + 1 }, NOW), /lifetime/u);

  const { entries, created } = createApproval([], { agentId: "claude", credentialId: "api", operationId: "post-x", minutes: 30 }, NOW);
  assert.match(created.id, /^appr-[0-9a-f]{18}$/u);
  assert.equal(created.expires_at, "2026-11-06T12:30:00.000Z");
  assert.equal(approvalState(created, NOW), "active");
  assert.equal(approvalState(created, new Date("2026-11-06T12:31:00Z")), "expired");

  const revoked = revokeApproval(entries, created.id);
  assert.equal(revoked && approvalState(revoked[0]!, NOW), "revoked");
  assert.equal(revokeApproval(entries, "missing"), null);

  const hand = parseApprovals(JSON.stringify([{ id: "a1", agent_id: "x", credential_id: "y", operation_id: "z", expires_at: "2026-01-01T00:00:00Z", note: "kept" }, { id: 5 }, "junk"]));
  assert.equal(hand.length, 1);
  assert.equal(hand[0]?.["note"], "kept");
  assert.deepEqual(pruneApprovals(hand, 7, NOW), [], "an approval long expired is dropped");
});

// ---- rotation metadata and presets ---------------------------------------

void test("rotation keeps the expiry and note and is not lost by later edits", () => {
  let file = applyMetaUpdate(EMPTY_META, "itch", { expires: "2027-01-01", note: "butler uploads" }, NOW);
  file = markRotated(file, "itch", NOW);
  assert.equal(file.keys["itch"]?.rotatedAt, NOW.toISOString());
  assert.equal(file.keys["itch"]?.expires, "2027-01-01");
  file = applyMetaUpdate(file, "itch", { expires: "2027-02-01", note: "butler uploads" }, NOW);
  assert.equal(file.keys["itch"]?.rotatedAt, NOW.toISOString());
  const rotatedOnly = markRotated(EMPTY_META, "new-key", NOW);
  assert.equal(rotatedOnly.keys["new-key"]?.expires, null);
});

void test("the provider table is internally consistent: unique ids, https addresses, safe key links", () => {
  const presets = listPresets();
  assert.equal(new Set(presets.map((p) => p.id)).size, presets.length, "preset ids are unique");
  for (const preset of presets) {
    assert.match(preset.baseUrl, /^https:\/\//u, `${preset.id} must use https`);
    assert.ok(preset.kind !== "query", `${preset.id} must not send keys in the URL`);
    if (preset.kind === "header") assert.ok(preset.paramName, `${preset.id} needs a header name`);
    const hit = findPresetByOrigin(preset.baseUrl);
    assert.ok(hit, `${preset.id} resolves by origin`);
    if (hit.keysUrl) assert.match(hit.keysUrl, /^https:\/\//u);
  }
  assert.equal(findPresetByOrigin("https://api.itch.io")?.keysUrl, "https://itch.io/user/settings/api-keys");
  assert.equal(findPresetByOrigin("https://unknown.example.org"), null);
});
