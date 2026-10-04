import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
import { once } from "node:events";
import { createServer } from "node:http";
import { mkdtemp, readFile, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { createInterface } from "node:readline";
import test from "node:test";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

const exec = promisify(execFile);
const root = fileURLToPath(new URL("../", import.meta.url));
const secret = "synthetic-broker-secret-12345";
const foreignSecret = "synthetic-other-principal-98765";

// Exercise the installed executable over the actual newline-delimited MCP
// transport. The harness has no imports from this repository's source/build.
function connect(entry, cwd, env) {
  const child = spawn(process.execPath, [entry], { cwd, env, stdio: "pipe", windowsHide: true });
  const pending = new Map();
  const lines = createInterface({ input: child.stdout });
  let nextId = 0;
  let output = "";
  let stderr = "";
  let terminalError;
  const fail = (error) => {
    terminalError = error;
    for (const request of pending.values()) request.reject(error);
    pending.clear();
  };
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  child.on("error", fail);
  const closed = new Promise((resolve) => child.on("close", (code) => {
    fail(new Error(`Installed broker closed (${code}): ${stderr}`));
    resolve(code);
  }));
  lines.on("line", (line) => {
    output += `${line}\n`;
    try {
      const message = JSON.parse(line);
      if (message.id === undefined) return;
      const request = pending.get(message.id);
      if (!request) return;
      pending.delete(message.id);
      if (message.error) request.reject(new Error(JSON.stringify(message.error)));
      else request.resolve(message.result);
    } catch (error) { fail(error); }
  });
  return {
    request(method, params = {}) {
      if (terminalError) return Promise.reject(terminalError);
      const id = ++nextId;
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          pending.delete(id);
          reject(new Error(`MCP request timed out: ${method}`));
        }, 15_000);
        pending.set(id, {
          resolve(value) { clearTimeout(timer); resolve(value); },
          reject(error) { clearTimeout(timer); reject(error); },
        });
        child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`, (error) => {
          if (error) fail(error);
        });
      });
    },
    notify(method) { child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method })}\n`); },
    transcript() { return output + stderr; },
    async close() {
      child.stdin.end();
      const timer = setTimeout(() => child.kill(), 3_000);
      try { await closed; } finally { clearTimeout(timer); lines.close(); }
    },
  };
}

test("clean-installed package enforces its stdio boundary", { timeout: 180_000 }, async (t) => {
  const scratch = await mkdtemp(path.join(tmpdir(), "broker-package-proof-"));
  let client;
  let upstream;
  t.after(async () => {
    if (client) await client.close();
    if (upstream?.listening) {
      upstream.closeAllConnections();
      await new Promise((resolve) => upstream.close(resolve));
    }
    // Only remove the unique directory created by this test.
    assert.equal(path.dirname(scratch), path.resolve(tmpdir()));
    assert.ok(path.basename(scratch).startsWith("broker-package-proof-"));
    await rm(scratch, { recursive: true, force: true });
  });
  const npmCli = process.env.npm_execpath;
  assert.ok(npmCli, "Run this proof with npm run test:e2e");
  const npm = (args, cwd) => exec(process.execPath, [npmCli, ...args], {
    cwd, timeout: 90_000, maxBuffer: 4 * 1024 * 1024, windowsHide: true,
  });
  const packed = JSON.parse((await npm(["pack", "--json", "--pack-destination", scratch], root)).stdout)[0];
  assert.ok(packed.files.every(({ path: name }) => !/^(scripts|test|data)\//u.test(name)));
  const consumer = path.join(scratch, "consumer with spaces");
  await mkdir(consumer);
  await writeFile(path.join(consumer, "package.json"), JSON.stringify({ name: "synthetic-broker-consumer", private: true }));
  await npm(["install", "--omit=dev", "--no-audit", "--no-fund", path.join(scratch, packed.filename)], consumer);
  const installed = path.join(consumer, "node_modules", "@sarutobi-sasuke", "credential-broker-mcp");
  const manifest = JSON.parse(await readFile(path.join(installed, "package.json"), "utf8"));
  const entry = path.join(installed, manifest.bin["credential-broker-stdio"]);
  assert.ok((await readFile(entry, "utf8")).startsWith("#!/usr/bin/env node"));
  await readFile(path.join(installed, manifest.bin["credential-broker-keys"]));

  const hits = [];
  upstream = createServer((req, res) => {
    hits.push({ method: req.method, url: req.url, authenticated: req.headers.authorization === `Bearer ${secret}` });
    res.setHeader("content-type", "application/json");
    res.setHeader("set-cookie", `private=${secret}`);
    res.end(JSON.stringify({ marker: "synthetic-response-body", raw: secret, encoded: Buffer.from(secret).toString("base64") }));
  });
  upstream.listen(0, "127.0.0.1");
  await once(upstream, "listening");
  const base = `http://127.0.0.1:${upstream.address().port}`;
  const policyFile = path.join(consumer, "broker.yaml");
  const auditFile = path.join(consumer, "audit.jsonl");
  const approvalsFile = path.join(consumer, "approvals.json");
  const policy = `version: 2
credentials:
  - id: fixture
    kind: bearer
    env_var: BROKER_PROOF_SECRET
    base_url: ${base}
  - id: foreign
    kind: bearer
    env_var: BROKER_PROOF_FOREIGN
    base_url: ${base}
agents:
  - id: proof-reader
    grants:
      - credential: fixture
        operations:
          - id: read-data
            method: GET
            path: /data/**
            query_params: [q]
            response_body: true
          - id: metadata-only
            method: GET
            path: /metadata
          - id: delete-item
            method: DELETE
            path: /items/*
            requires_approval: true
            requires_idempotency_key: true
        deny: [/data/private/**]
  - id: other-principal
    grants:
      - credential: foreign
        operations:
          - id: other-read
            method: GET
            path: /**
`;
  await writeFile(policyFile, policy);
  // Do not inherit operator credentials, runtime config or NODE_OPTIONS.
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => /^(PATH|SYSTEMROOT|WINDIR|TEMP|TMP)$/iu.test(key)));
  Object.assign(env, {
    BROKER_AGENT_ID: "proof-reader", BROKER_POLICY_FILE: policyFile,
    BROKER_AUDIT_FILE: auditFile, BROKER_APPROVALS_FILE: approvalsFile,
    BROKER_PROOF_SECRET: secret, BROKER_PROOF_FOREIGN: foreignSecret,
  });

  await t.test("missing and unknown launcher identities fail closed", async () => {
    for (const id of [undefined, "unknown-principal"]) {
      const launchEnv = { ...env };
      if (id === undefined) delete launchEnv.BROKER_AGENT_ID;
      else launchEnv.BROKER_AGENT_ID = id;
      await assert.rejects(exec(process.execPath, [entry], { cwd: consumer, env: launchEnv, timeout: 10_000, windowsHide: true }),
        (error) => error.code === 1 && /required|not provisioned/u.test(error.stderr));
    }
    assert.equal(hits.length, 0);
  });

  client = connect(entry, consumer, env);
  const initialized = await client.request("initialize", {
    protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "synthetic-package-proof", version: "1.0.0" },
  });
  assert.equal(initialized.serverInfo.name, "credential-broker-mcp");
  client.notify("notifications/initialized");
  const call = (name, args = {}) => client.request("tools/call", { name, arguments: args });

  await t.test("tool discovery and credential metadata remain principal-scoped", async () => {
    const { tools } = await client.request("tools/list");
    assert.deepEqual(tools.map(({ name }) => name).sort(), ["broker_explain_request", "broker_list_credentials", "broker_mutate", "broker_read", "broker_whoami"]);
    assert.equal(tools.find(({ name }) => name === "broker_mutate").annotations.destructiveHint, true);
    assert.equal(tools.find(({ name }) => name === "broker_read").annotations.readOnlyHint, true);
    assert.equal((await call("broker_whoami")).structuredContent.agent_id, "proof-reader");
    const listed = (await call("broker_list_credentials")).structuredContent.credentials;
    assert.deepEqual(listed.map(({ id }) => id), ["fixture"]);
    assert.equal(listed[0].provisioned, true);
  });

  await t.test("dry runs and denied requests never reach the upstream", async () => {
    const allowed = await call("broker_explain_request", { credential: "fixture", method: "GET", url: `${base}/data/item` });
    assert.equal(allowed.structuredContent.allowed, true);
    for (const [args, reason] of [
      [{ credential: "foreign", url: `${base}/data/item` }, /no grant/u],
      [{ credential: "fixture", url: "https://example.invalid/data/item" }, /outside credential/u],
      [{ credential: "fixture", url: `${base}/data/private/item` }, /Denied by rule/u],
      [{ credential: "fixture", url: `${base}/data/%70rivate/item` }, /Denied by rule/u],
      [{ credential: "fixture", url: `${base}/data/item?unexpected=1` }, /query parameter/iu],
      [{ credential: "fixture", url: `${base}/data/item`, method: "POST" }, /GET|HEAD/u],
    ]) {
      const denied = await call("broker_read", args);
      assert.equal(denied.isError, true, JSON.stringify(args));
      // A network or provisioning failure must not masquerade as a policy denial.
      assert.match(denied.content[0].text, reason);
    }
    assert.equal(hits.length, 0);
  });

  await t.test("real loopback reads inject credentials and redact responses", async () => {
    const result = await call("broker_read", { credential: "fixture", url: `${base}/data/item?q=synthetic-private-query` });
    assert.equal(result.isError, undefined);
    assert.equal(result.structuredContent.status, 200);
    assert.match(result.structuredContent.body, /synthetic-response-body/u);
    assert.equal(hits[0].authenticated, true);
    assert.equal(result.structuredContent.headers["set-cookie"], undefined);
    const metadata = await call("broker_read", { credential: "fixture", url: `${base}/metadata` });
    assert.equal(metadata.structuredContent.status, 200);
    assert.equal(metadata.structuredContent.body, undefined);
    assert.ok(metadata.structuredContent.body_withheld);
  });

  await t.test("installed mutation path checks approval, idempotency and live revocation", async () => {
    const args = { credential: "fixture", method: "DELETE", url: `${base}/items/synthetic-item` };
    const before = hits.length;
    assert.equal((await call("broker_mutate", args)).isError, true);
    const approval = { id: "synthetic-approval", agent_id: "proof-reader", credential_id: "fixture", operation_id: "delete-item", expires_at: new Date(Date.now() + 60_000).toISOString() };
    await writeFile(approvalsFile, JSON.stringify([approval]));
    assert.equal((await call("broker_mutate", { ...args, approval_id: approval.id })).isError, true);
    assert.equal(hits.length, before);
    const approved = { ...args, approval_id: approval.id, idempotency_key: "synthetic-request-1" };
    assert.equal((await call("broker_mutate", approved)).structuredContent.status, 200);
    assert.equal(hits.at(-1).method, "DELETE");
    const records = (await readFile(auditFile, "utf8")).trim().split("\n").map((line) => JSON.parse(line));
    assert.ok(records.some((record) => record.outcome === "succeeded" && record.idempotencyKey === approved.idempotency_key));
    await writeFile(approvalsFile, JSON.stringify([{ ...approval, revoked: true }]));
    assert.equal((await call("broker_mutate", approved)).isError, true);
    assert.equal(hits.length, before + 1);
  });

  await t.test("protocol and audit output contain no secrets or response bodies in audit", async () => {
    const audit = await readFile(auditFile, "utf8");
    const output = audit + client.transcript();
    for (const value of [secret, foreignSecret, Buffer.from(secret).toString("base64")]) assert.ok(!output.includes(value));
    assert.ok(!audit.includes("synthetic-response-body"));
    assert.ok(!audit.includes("synthetic-private-query"));
    const outcomes = audit.trim().split("\n").map((line) => JSON.parse(line).outcome);
    for (const outcome of ["requested", "denied", "approved", "executing", "succeeded"]) assert.ok(outcomes.includes(outcome));
  });
  await t.test("unsupported policy fields prevent installed-server startup", async () => {
    for (const [invalid, reason] of [
      [policy.replace("version: 2", "version: 2\nunknown_policy_field: true"), /unknown_policy_field/u],
      [policy.replace("  - id: proof-reader", "  - id: proof-reader\n    enabeld: false"), /enabeld/u],
    ]) {
      await writeFile(policyFile, invalid);
      await assert.rejects(exec(process.execPath, [entry], { cwd: consumer, env, timeout: 10_000, windowsHide: true }),
        (error) => error.code === 1 && reason.test(error.stderr));
    }
  });
  t.diagnostic(`Packaged ${manifest.name}@${manifest.version}; tarball integrity ${packed.integrity}`);
});
