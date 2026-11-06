import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, rm, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { applyPause, checkPause, EMPTY_PAUSE, FilePauseGuard, parsePauseState, reconcilePause, serializePauseState } from "../src/kill-switch.js";
import { changePause, confirmationMatches, pauseAuditRecord, pauseStateFromAudit, readPauseFile } from "../src/pause-admin.js";

import type { PauseFileEvent } from "../src/kill-switch.js";

const T0 = new Date("2026-11-06T12:00:00Z");
const T1 = new Date("2026-11-06T12:05:00Z");
const T_BEFORE = new Date("2026-11-06T11:00:00Z");
const REASON = "key leaked on pastebin";

async function withTempDir<T>(run: (dir: string) => Promise<T>): Promise<T> {
  const dir = await mkdtemp(join(tmpdir(), "broker-pause-"));
  try {
    return await run(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

async function auditLines(file: string): Promise<Record<string, unknown>[]> {
  if (!existsSync(file)) return [];
  return (await readFile(file, "utf8")).split("\n").filter(Boolean).map((line) => JSON.parse(line) as Record<string, unknown>);
}

// ---- typed confirmation ----------------------------------------------------

void test("the typed word is case-insensitive, trimmed, and must match the direction", () => {
  assert.ok(confirmationMatches("PAUSE", true));
  assert.ok(confirmationMatches("  pause ", true));
  assert.ok(confirmationMatches("Resume", false));
  assert.equal(confirmationMatches("PAUSE", false), false, "PAUSE does not resume");
  assert.equal(confirmationMatches("RESUME", true), false, "RESUME does not pause");
  assert.equal(confirmationMatches("PAUS", true), false);
  assert.equal(confirmationMatches("", true), false);
  assert.equal(confirmationMatches(undefined, false), false);
});

// ---- resume records and reconciliation -------------------------------------

void test("every resume writes an explicit record and bumps the revision; the file state is never emptied", () => {
  const paused = applyPause(EMPTY_PAUSE, { kind: "all" }, true, REASON, T0);
  assert.equal(paused.revision, 1);
  assert.deepEqual(paused.resumed, []);
  const resumed = applyPause(paused, { kind: "all" }, false, "", T1);
  assert.equal(resumed.all, null);
  assert.equal(resumed.revision, 2);
  assert.deepEqual(resumed.resumed, [{ scope: "all", at: T1.toISOString() }]);
  const again = applyPause(resumed, { kind: "agent", id: "claude" }, false, "", T1);
  assert.deepEqual(again.resumed.at(-1), { scope: "agent:claude", at: T1.toISOString() }, "resuming something not paused still leaves a record");
  const roundTrip = parsePauseState(serializePauseState(again));
  assert.ok(roundTrip.ok && roundTrip.state.resumed.length === 2);
  assert.doesNotMatch(JSON.stringify(again.resumed), /pastebin/u, "resume records never carry the reason");
});

void test("old pause files without revision or resume records still parse", () => {
  const parsed = parsePauseState(JSON.stringify({ version: 1, all: { at: T0.toISOString(), reason: "" }, agents: {}, credentials: {} }));
  assert.ok(parsed.ok);
  assert.equal(parsed.ok && parsed.state.revision, 0);
  assert.deepEqual(parsed.ok && parsed.state.resumed, []);
});

void test("a pause that vanishes from the file is held unless a resume record dated at or after it exists", () => {
  const enforced = applyPause(applyPause(EMPTY_PAUSE, { kind: "all" }, true, REASON, T0), { kind: "agent", id: "codex" }, true, "", T0);

  // Replaced by an empty but valid file: both pauses held.
  const dropped = reconcilePause(enforced, EMPTY_PAUSE);
  assert.deepEqual(dropped.held, [{ kind: "all" }, { kind: "agent", id: "codex" }]);
  assert.ok(dropped.effective.all, "all stays paused");
  assert.ok(dropped.effective.agents["codex"], "the agent stays paused");

  // A resume record older than the pause does not count.
  const stale = { ...EMPTY_PAUSE, resumed: [{ scope: "all", at: T_BEFORE.toISOString() }] };
  assert.deepEqual(reconcilePause(enforced, stale).held, [{ kind: "all" }, { kind: "agent", id: "codex" }]);

  // A proper resume of "all" releases only "all".
  const partly = applyPause(enforced, { kind: "all" }, false, "", T1);
  const halfway = reconcilePause(enforced, partly);
  assert.deepEqual(halfway.held, []);
  assert.equal(halfway.effective.all, null);
  assert.ok(halfway.effective.agents["codex"], "the agent pause is still in the file");

  // Resuming both releases both, and says so.
  const fully = applyPause(partly, { kind: "agent", id: "codex" }, false, "", T1);
  assert.deepEqual(reconcilePause(enforced, fully), { effective: fully, held: [], released: [{ kind: "all" }, { kind: "agent", id: "codex" }] });

  // With nothing enforced yet, the file is taken as it is.
  assert.deepEqual(reconcilePause(null, EMPTY_PAUSE), { effective: EMPTY_PAUSE, held: [], released: [] });
});

// ---- the broker guard against a deleted, truncated or replaced file ---------

void test("the broker stays paused when the pause file is deleted, truncated or replaced, reports it once, and only a valid resume releases it", async () => {
  await withTempDir(async (dir) => {
    const file = join(dir, "pause.json");
    const events: PauseFileEvent[] = [];
    const guard = new FilePauseGuard(file, (event) => {
      events.push(event);
    });

    assert.deepEqual(await guard.check("claude", "api"), { paused: false }, "no file, nothing enforced yet: open");

    await writeFile(file, serializePauseState(applyPause(EMPTY_PAUSE, { kind: "all" }, true, REASON, T0)));
    assert.equal((await guard.check("claude", "api")).paused, true);

    // Deleted: the last pause stays in force.
    await unlink(file);
    assert.equal((await guard.check("claude", "api")).paused, true, "deleting the file does not resume");
    assert.equal((await guard.check("codex", "other")).paused, true);
    assert.equal(events.length, 1, "reported once, not on every request");
    assert.equal(events[0]?.kind, "missing");

    // Truncated: fail closed and report.
    await writeFile(file, "");
    const truncated = await guard.check("claude", "api");
    assert.equal(truncated.paused && truncated.scope, "unreadable");
    assert.equal(events.at(-1)?.kind, "invalid");

    // Replaced with a valid file that shows nothing paused and no resume record: held.
    await writeFile(file, serializePauseState(EMPTY_PAUSE));
    assert.equal((await guard.check("claude", "api")).paused, true, "a fresh empty file does not resume");
    assert.equal(events.at(-1)?.kind, "held");
    const heldCount = events.length;
    await guard.check("claude", "api");
    assert.equal(events.length, heldCount, "the same held state is not reported again");

    // A valid file with an explicit resume record releases it, and the release is reported.
    await writeFile(file, serializePauseState(applyPause(EMPTY_PAUSE, { kind: "all" }, false, "", T1)));
    assert.deepEqual(await guard.check("claude", "api"), { paused: false });
    assert.equal(events.length, heldCount + 1, "a clean resume produces one released event");
    assert.equal(events.at(-1)?.kind, "released");

    // After release, deleting the file no longer pauses anything.
    await unlink(file);
    assert.deepEqual(await guard.check("claude", "api"), { paused: false });

    for (const event of events) assert.doesNotMatch(JSON.stringify(event), /pastebin/u, "events never carry the reason");
  });
});

void test("a failing event handler never opens access", async () => {
  await withTempDir(async (dir) => {
    const file = join(dir, "pause.json");
    const guard = new FilePauseGuard(file, () => Promise.reject(new Error("audit disk full")));
    await writeFile(file, serializePauseState(applyPause(EMPTY_PAUSE, { kind: "credential", id: "api" }, true, "", T0)));
    assert.equal((await guard.check("claude", "api")).paused, true);
    await unlink(file);
    assert.equal((await guard.check("claude", "api")).paused, true);
  });
});

// ---- the shared change path used by the page and the CLI --------------------

void test("changePause never deletes the file, repairs an unreadable one, and audits every change without the reason", async () => {
  await withTempDir(async (dir) => {
    const file = join(dir, "pause.json");
    const audit = join(dir, "audit.jsonl");

    const on = await changePause({ file, auditFile: audit, source: "page", now: T0 }, { scope: { kind: "all" }, active: true, reason: REASON, undo: false });
    assert.equal(on.changed, true);
    assert.ok(existsSync(file));

    const off = await changePause({ file, auditFile: audit, source: "page", now: T1 }, { scope: { kind: "all" }, active: false, reason: "", undo: false });
    assert.equal(off.changed, true);
    assert.ok(existsSync(file), "resuming keeps the file");
    const after = await readPauseFile(file);
    assert.equal(after.state.all, null);
    assert.deepEqual(after.state.resumed, [{ scope: "all", at: T1.toISOString() }]);

    const repeat = await changePause({ file, auditFile: audit, source: "cli" }, { scope: { kind: "all" }, active: false, reason: "", undo: false });
    assert.equal(repeat.changed, false, "resuming twice is reported as no change");

    const undo = await changePause({ file, auditFile: audit, source: "page" }, { scope: { kind: "agent", id: "claude" }, active: true, reason: "", undo: false });
    assert.equal(undo.changed, true);
    await changePause({ file, auditFile: audit, source: "page" }, { scope: { kind: "agent", id: "claude" }, active: false, reason: "", undo: true });

    // An unreadable file is rewritten, and a resume of everything then releases a holding broker.
    await writeFile(file, "{ broken");
    const repaired = await changePause({ file, auditFile: audit, source: "cli" }, { scope: { kind: "all" }, active: false, reason: "", undo: false });
    assert.equal(repaired.repaired, true);
    assert.equal(repaired.changed, true);
    assert.ok((await readPauseFile(file)).state.resumed.some((r) => r.scope === "all"));

    const lines = await auditLines(audit);
    assert.deepEqual(
      lines.map((l) => [l["method"], l["pathname"], l["detail"]]),
      [
        ["PAUSE", "/all", "page"],
        ["RESUME", "/all", "page"],
        ["RESUME", "/all", "cli"],
        ["PAUSE", "/agent/claude", "page"],
        ["RESUME", "/agent/claude", "page undo"],
        ["RESUME", "/all", "cli"],
      ],
    );
    for (const line of lines) {
      assert.equal(line["agentId"], "operator");
      assert.equal(typeof line["at"], "string");
      assert.doesNotMatch(JSON.stringify(line), /pastebin/u, "the audit never holds the reason");
    }
  });
});

void test("the audit record for a pause change is content-free by construction", () => {
  const record = pauseAuditRecord({ kind: "credential", id: "github" }, true, "cli", false);
  assert.deepEqual(Object.keys(record).sort(), ["agentId", "credentialId", "detail", "host", "method", "outcome", "pathname", "traceId"]);
  assert.equal(record.pathname, "/credential/github");
  assert.equal(record.detail, "cli");
});

// ---- the real binaries -----------------------------------------------------

const distSrc = fileURLToPath(new URL("../src/", import.meta.url));

function run(entry: string, args: string[], env: NodeJS.ProcessEnv): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolveRun, reject) => {
    const child = spawn(process.execPath, [join(distSrc, entry), ...args], { env, stdio: "pipe", windowsHide: true });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk: Buffer) => {
      stdout += chunk.toString();
    });
    child.stderr.on("data", (chunk: Buffer) => {
      stderr += chunk.toString();
    });
    child.on("error", reject);
    child.on("close", (code) => resolveRun({ code, stdout, stderr }));
  });
}

void test("the pause command acts at once, prints what changed, keeps the file on resume, and writes audit lines", async () => {
  await withTempDir(async (dir) => {
    const policyFile = join(dir, "broker.yaml");
    const auditFile = join(dir, "audit.jsonl");
    const pauseFile = join(dir, "pause.json");
    const env = { ...process.env, BROKER_POLICY_FILE: policyFile, BROKER_AUDIT_FILE: auditFile };

    const on = await run("pause-cli.js", ["on", "--reason", REASON, "--yes"], env);
    assert.equal(on.code, 0, on.stderr);
    assert.match(on.stdout, /Changed: all agent access is now PAUSED/u);
    assert.ok(existsSync(pauseFile));

    const status = await run("pause-cli.js", ["status"], env);
    assert.equal(status.code, 1, "exit 1 while paused");
    assert.match(status.stdout, /ALL agent access is paused/u);

    const off = await run("pause-cli.js", ["off"], env);
    assert.equal(off.code, 0, off.stderr);
    assert.match(off.stdout, /Changed: all agent access is now resumed/u);
    assert.ok(existsSync(pauseFile), "off never deletes the file");
    const state = await readPauseFile(pauseFile);
    assert.equal(state.state.all, null);
    assert.equal(state.state.resumed.length, 1);

    const lines = await auditLines(auditFile);
    assert.deepEqual(lines.map((l) => [l["method"], l["detail"]]), [["PAUSE", "cli"], ["RESUME", "cli"]]);
    assert.doesNotMatch(JSON.stringify(lines), /pastebin/u);
  });
});

void test("the key manager refuses a global pause or resume without the typed word, and never deletes the file", async () => {
  await withTempDir(async (dir) => {
    const policyFile = join(dir, "broker.yaml");
    const auditFile = join(dir, "audit.jsonl");
    const pauseFile = join(dir, "pause.json");
    await writeFile(policyFile, "version: 2\ncredentials: []\nagents: []\n");
    const env = { ...process.env, BROKER_POLICY_FILE: policyFile, BROKER_AUDIT_FILE: auditFile, BROKER_KEYCHAIN: "off", BROKER_KEYS_PORT: "0" };
    const child = spawn(process.execPath, [join(distSrc, "keys-ui.js"), "--no-open"], { env, stdio: "pipe", windowsHide: true });
    try {
      const url = await new Promise<string>((resolveUrl, reject) => {
        let out = "";
        child.stdout.on("data", (chunk: Buffer) => {
          out += chunk.toString();
          const hit = /Open:\s+(http:\/\/127\.0\.0\.1:\d+\/#[0-9a-f]+)/u.exec(out);
          if (hit?.[1]) resolveUrl(hit[1]);
        });
        child.on("error", reject);
        child.on("close", (code) => reject(new Error(`key manager exited early (${code})`)));
      });
      const base = url.split("#")[0] ?? "";
      const token = url.split("#")[1] ?? "";
      const call = async (body: unknown): Promise<{ status: number; json: Record<string, unknown> }> => {
        const res = await fetch(`${base}api/pause`, {
          method: "POST",
          headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
          body: JSON.stringify(body),
        });
        return { status: res.status, json: (await res.json()) as Record<string, unknown> };
      };

      const wrong = await call({ scope: { kind: "all" }, active: true, confirm: "yes" });
      assert.equal(wrong.status, 400);
      assert.match(String(wrong.json["error"]), /Type PAUSE/u);
      assert.equal(existsSync(pauseFile), false, "a refused request writes nothing");

      const right = await call({ scope: { kind: "all" }, active: true, confirm: " pause ", reason: REASON });
      assert.equal(right.status, 200);
      assert.ok(existsSync(pauseFile));

      const wrongWord = await call({ scope: { kind: "all" }, active: false, confirm: "PAUSE" });
      assert.equal(wrongWord.status, 400);
      assert.match(String(wrongWord.json["error"]), /Type RESUME/u);

      const resumed = await call({ scope: { kind: "all" }, active: false, confirm: "resume" });
      assert.equal(resumed.status, 200);
      assert.ok(existsSync(pauseFile), "the page never deletes the file");
      assert.equal((await readPauseFile(pauseFile)).state.all, null);

      // Narrower scopes need no word from the server's side; the page confirms them itself.
      const agentOn = await call({ scope: { kind: "agent", id: "claude" }, active: true });
      assert.equal(agentOn.status, 200);
      const agentUndo = await call({ scope: { kind: "agent", id: "claude" }, active: false, undo: true });
      assert.equal(agentUndo.status, 200);

      const lines = await auditLines(auditFile);
      assert.deepEqual(lines.map((l) => [l["method"], l["pathname"], l["detail"]]), [
        ["PAUSE", "/all", "page"],
        ["RESUME", "/all", "page"],
        ["PAUSE", "/agent/claude", "page"],
        ["RESUME", "/agent/claude", "page undo"],
      ]);
      assert.doesNotMatch(JSON.stringify(lines), /pastebin/u);
    } finally {
      child.kill();
    }
  });
});

// ---- review fixes: releases are audited, rollbacks are held, restarts remember ----

void test("a release that arrives through the file is reported, so a forged resume record leaves a trace", async () => {
  await withTempDir(async (dir) => {
    const file = join(dir, "pause.json");
    const events: PauseFileEvent[] = [];
    const guard = new FilePauseGuard(file, (event) => {
      events.push(event);
    });
    await writeFile(file, serializePauseState(applyPause(EMPTY_PAUSE, { kind: "all" }, true, REASON, T0)));
    assert.equal((await guard.check("claude", "api")).paused, true);
    // Forged by hand: valid, resumed, future-dated record.
    await writeFile(file, JSON.stringify({ version: 1, revision: 999, all: null, agents: {}, credentials: {}, resumed: [{ scope: "all", at: "2099-01-01T00:00:00Z" }] }));
    assert.deepEqual(await guard.check("claude", "api"), { paused: false }, "the design cannot stop a same-user writer");
    assert.deepEqual(events.map((e) => e.kind), ["released"], "but it says so");
    assert.match(events[0]?.detail ?? "", /released by the file for all/u);
    assert.doesNotMatch(JSON.stringify(events), /pastebin/u);
  });
});

void test("a file whose revision went backwards is held even when it carries a resume record", () => {
  const paused = applyPause(applyPause(EMPTY_PAUSE, { kind: "all" }, true, "", T0), { kind: "agent", id: "x" }, true, "", T0);
  const resumed = applyPause(applyPause(paused, { kind: "all" }, false, "", T1), { kind: "agent", id: "x" }, false, "", T1);
  assert.equal(resumed.revision, 4);
  // The broker enforced the paused state at revision 4; an older copy of the
  // file (revision 1) with the resume records put back must not release.
  const enforced = { ...paused, revision: 4 };
  const out = reconcilePause(enforced, { ...resumed, revision: 1 });
  assert.deepEqual(out.held, [{ kind: "all" }, { kind: "agent", id: "x" }]);
  assert.deepEqual(out.released, []);
  assert.equal(out.effective.revision, 4, "the remembered revision is kept");
  // The same records at a newer revision do release.
  assert.deepEqual(reconcilePause(enforced, { ...resumed, revision: 5 }).released, [{ kind: "all" }, { kind: "agent", id: "x" }]);
  // An unparseable pause time counts as the beginning, so a record can still release it.
  const unparseable = { ...enforced, all: { at: "not a date", reason: "" } };
  const releasedAnyway = reconcilePause(unparseable, { ...applyPause(EMPTY_PAUSE, { kind: "all" }, false, "", T1), revision: 5 });
  assert.deepEqual(releasedAnyway.released, [{ kind: "all" }]);
  assert.deepEqual(releasedAnyway.held, [{ kind: "agent", id: "x" }], "the agent pause has no record and stays held");
});

void test("the audit log rebuilds the pause state a restarted broker must still hold", async () => {
  const lines = [
    { at: T0.toISOString(), method: "PAUSE", pathname: "/all", agentId: "operator" },
    { at: T0.toISOString(), method: "PAUSE", pathname: "/agent/codex", agentId: "operator" },
    { at: T1.toISOString(), method: "RESUME", pathname: "/all", agentId: "operator" },
    { at: T1.toISOString(), method: "PAUSE", pathname: "/credential/api", agentId: "operator" },
    { at: T1.toISOString(), method: "GET", pathname: "/all", agentId: "claude", outcome: "denied" },
    { at: T1.toISOString(), method: "PAUSE", pathname: "/agent/Not Valid", agentId: "operator" },
  ].map((l) => JSON.stringify(l));
  lines.push("junk", "");
  const state = pauseStateFromAudit(lines);
  assert.equal(state.all, null);
  assert.ok(state.agents["codex"]);
  assert.ok(state.credentials["api"]);
  assert.equal(Object.keys(state.agents).length, 1);

  await withTempDir(async (dir) => {
    const file = join(dir, "pause.json");
    const events: PauseFileEvent[] = [];
    // File deleted while the broker was down, then the broker starts.
    const guard = new FilePauseGuard(file, (event) => {
      events.push(event);
    });
    guard.prime(state);
    assert.equal((await guard.check("codex", "other")).paused, true, "held from the audit log");
    assert.equal((await guard.check("claude", "api")).paused, true);
    assert.deepEqual(await guard.check("claude", "other"), { paused: false });
    assert.equal(events[0]?.kind, "missing");
    // A proper resume through the admin path releases it.
    await changePause({ file, auditFile: null, source: "cli", now: new Date("2026-11-06T13:00:00Z") }, { scope: { kind: "agent", id: "codex" }, active: false, reason: "", undo: false });
    assert.deepEqual(await guard.check("codex", "other"), { paused: false });
    assert.equal((await guard.check("claude", "api")).paused, true, "the other pause is still held");
    // Priming never overrides a state already enforced.
    guard.prime(applyPause(EMPTY_PAUSE, { kind: "all" }, true, "", T0));
    assert.deepEqual(await guard.check("codex", "other"), { paused: false });
  });
});

void test("repairing an unreadable file keeps everything paused unless the request is the resume of all", async () => {
  await withTempDir(async (dir) => {
    const file = join(dir, "pause.json");
    const audit = join(dir, "audit.jsonl");
    await writeFile(file, "{ broken");
    await changePause({ file, auditFile: audit, source: "page", now: T0 }, { scope: { kind: "agent", id: "claude" }, active: true, reason: "", undo: false });
    const repaired = await readPauseFile(file);
    assert.equal(repaired.unreadable, false);
    assert.ok(repaired.state.all, "everything stays paused after the repair");
    assert.ok(repaired.state.agents["claude"]);
    const lines = await auditLines(audit);
    assert.deepEqual(lines.map((l) => [l["method"], l["pathname"], l["detail"]]), [["PAUSE", "/agent/claude", "page"], ["PAUSE", "/all", "page repair"]]);
    await changePause({ file, auditFile: audit, source: "cli", now: T1 }, { scope: { kind: "all" }, active: false, reason: "", undo: false });
    assert.equal((await readPauseFile(file)).state.all, null);
  });
});

void test("an agent id that names a prototype property is not treated as paused", () => {
  const state = applyPause(EMPTY_PAUSE, { kind: "credential", id: "api" }, true, "", T0);
  assert.deepEqual(checkPause(state, "constructor", "toString"), { paused: false });
  assert.deepEqual(checkPause(state, "__proto__", "api").paused, true);
});
