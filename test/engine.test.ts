import assert from "node:assert/strict";
import { createServer } from "node:http";
import test from "node:test";

import { MemoryAuditSink } from "../src/audit.js";
import { BrokerEngine, EnvSecretProvider, InMemoryApprovalStore } from "../src/engine.js";
import { parseBrokerPolicy } from "../src/policy.js";

import type { AddressInfo } from "node:net";
import type { Clock, SecretProvider } from "../src/engine.js";
import type { BrokerPolicy } from "../src/types.js";

const SECRET = "test-secret-value-12345";
const OTHER_SECRET = "other-agents-secret-98765";

function policyFor(port: number): BrokerPolicy {
  return parseBrokerPolicy(`
version: 2
credentials:
  - id: local
    description: Loopback upstream (header credential)
    kind: header
    env_var: BROKER_TEST_SECRET
    param_name: x-api-key
    base_url: http://127.0.0.1:${port}
  - id: local-basic
    description: Loopback upstream (basic credential)
    kind: basic
    env_var: BROKER_TEST_BASIC
    base_url: http://127.0.0.1:${port}
  - id: local-query
    description: Loopback upstream (query credential)
    kind: query
    env_var: BROKER_TEST_QUERY
    param_name: appid
    base_url: http://127.0.0.1:${port}
    high_risk: true
  - id: foreign
    description: Credential granted to another agent only
    kind: header
    env_var: BROKER_TEST_FOREIGN
    param_name: x-api-key
    base_url: http://127.0.0.1:${port}
agents:
  - id: tester
    display_name: Tester
    enabled: true
    max_response_bytes: 64
    grants:
      - credential: local
        operations:
          - id: read-data
            method: GET
            path: /data
            response_body: true
            response_content_types: [application/json, text/plain]
          - id: read-big
            method: GET
            path: /big
            response_body: true
            response_content_types: [text/plain]
          - id: read-meta-only
            method: GET
            path: /meta
          - id: read-hop
            method: GET
            path: /hop
            response_body: true
          - id: post-echo
            method: POST
            path: /echo
            body:
              content_types: [application/json]
              max_bytes: 1024
            requires_approval: false
            response_body: true
            response_content_types: [application/json]
            max_response_bytes: 4096
          - id: delete-thing
            method: DELETE
            path: /thing/*
            requires_approval: true
            requires_idempotency_key: true
            response_body: true
            response_content_types: [application/json]
      - credential: local-basic
        operations:
          - id: read-echo-auth
            method: GET
            path: /echo-auth
            response_body: true
            response_content_types: [application/json, text/plain]
            max_response_bytes: 4096
      - credential: local-query
        operations:
          - id: read-weather
            method: GET
            path: /weather
            query_params: [q]
            response_body: true
            response_content_types: [application/json, text/plain]
            max_response_bytes: 4096
  - id: other-agent
    display_name: Other
    enabled: true
    grants:
      - credential: foreign
        operations:
          - id: read-anything
            method: GET
            path: /**
            response_body: true
`);
}

async function withUpstream(
  handler: Parameters<typeof createServer>[1],
  run: (port: number) => Promise<void>,
): Promise<void> {
  const server = createServer(handler);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  try {
    await run(port);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

interface EngineBundle {
  engine: BrokerEngine;
  audit: MemoryAuditSink;
  approvals: InMemoryApprovalStore;
  secrets: SecretProvider;
}

function makeEngine(
  port: number,
  overrides: { clock?: Clock; env?: Record<string, string | undefined> } = {},
): EngineBundle {
  const policy = policyFor(port);
  const env = overrides.env ?? {
    BROKER_TEST_SECRET: SECRET,
    BROKER_TEST_BASIC: SECRET,
    BROKER_TEST_QUERY: SECRET,
    BROKER_TEST_FOREIGN: OTHER_SECRET,
  };
  const secrets = new EnvSecretProvider(policy, "tester", { env });
  const audit = new MemoryAuditSink();
  const approvals = new InMemoryApprovalStore();
  const engine = new BrokerEngine({
    policy,
    principalId: "tester",
    secrets,
    audit,
    approvals,
    ...(overrides.clock ? { clock: overrides.clock } : {}),
    timeoutMs: 5_000,
  });
  return { engine, audit, approvals, secrets };
}

// ---------------------------------------------------------------------------
// Issue #3: no raw or wire-encoded secret escapes any output path
// ---------------------------------------------------------------------------

void test("header secret reaches the upstream and every echo of it is redacted", async () => {
  await withUpstream(
    (req, res) => {
      res.setHeader("content-type", "application/json");
      res.setHeader("set-cookie", "session=leaky");
      res.end(JSON.stringify({ got: req.headers["x-api-key"] }));
    },
    async (port) => {
      const { engine } = makeEngine(port);
      const result = await engine.execute({ credentialId: "local", method: "GET", url: `http://127.0.0.1:${port}/data` });
      assert.equal(result.kind, "success");
      assert.ok(result.kind === "success");
      assert.equal(result.status, 200);
      assert.ok(!JSON.stringify(result).includes(SECRET), "secret must never appear in the result");
      assert.ok(result.body?.includes("[REDACTED]"));
      assert.equal(result.headers["set-cookie"], undefined, "unsafe headers must be dropped");
    },
  );
});

void test("a Basic credential echoed as Base64 is redacted from the body", async () => {
  await withUpstream(
    (req, res) => {
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ auth: req.headers.authorization }));
    },
    async (port) => {
      const { engine } = makeEngine(port);
      const result = await engine.execute({
        credentialId: "local-basic",
        method: "GET",
        url: `http://127.0.0.1:${port}/echo-auth`,
      });
      assert.ok(result.kind === "success");
      const b64 = Buffer.from(SECRET, "utf8").toString("base64");
      assert.ok(!JSON.stringify(result).includes(b64), "Base64 form of the secret must be redacted");
      assert.ok(!JSON.stringify(result).includes(SECRET));
    },
  );
});

void test("a query credential reflected in an echoed URL is redacted, in raw and encoded form", async () => {
  await withUpstream(
    (req, res) => {
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ url: req.url, key: new URL(req.url ?? "/", "http://x").searchParams.get("appid") }));
    },
    async (port) => {
      const { engine } = makeEngine(port);
      const result = await engine.execute({
        credentialId: "local-query",
        method: "GET",
        url: `http://127.0.0.1:${port}/weather?q=London`,
      });
      assert.ok(result.kind === "success");
      const text = JSON.stringify(result);
      assert.ok(!text.includes(SECRET));
      assert.ok(!text.includes(encodeURIComponent(SECRET)));
    },
  );
});

void test("upstream error text never reaches the agent and audit detail is redacted", async () => {
  const { engine, audit } = await (async () => {
    // Point at a port with no listener to force a network error.
    const bundle = makeEngine(1);
    return bundle;
  })();
  const result = await engine.execute({ credentialId: "local", method: "GET", url: "http://127.0.0.1:1/data" });
  assert.equal(result.kind, "error");
  assert.ok(result.kind === "error");
  assert.equal(result.outcome, "failed");
  assert.ok(!result.message.includes(SECRET));
  assert.ok(!result.message.toLowerCase().includes("econnrefused"), "raw upstream error text must not be relayed");
  for (const record of audit.records) {
    assert.ok(!JSON.stringify(record).includes(SECRET));
  }
});

void test("truncation cannot leak a partial secret and metadata reports it", async () => {
  await withUpstream(
    (_req, res) => {
      res.setHeader("content-type", "text/plain");
      // Position the secret so the 64-byte cap cuts it mid-way.
      res.end("x".repeat(50) + SECRET + "y".repeat(100));
    },
    async (port) => {
      const { engine } = makeEngine(port);
      const result = await engine.execute({ credentialId: "local", method: "GET", url: `http://127.0.0.1:${port}/big` });
      assert.ok(result.kind === "success");
      assert.equal(result.truncated, true);
      assert.ok(!result.body?.includes(SECRET.slice(0, 8)), "no secret prefix may survive the byte cap");
    },
  );
});

void test("metadata-only operations withhold the body entirely", async () => {
  await withUpstream(
    (_req, res) => {
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ sensitive: "payload" }));
    },
    async (port) => {
      const { engine } = makeEngine(port);
      const result = await engine.execute({ credentialId: "local", method: "GET", url: `http://127.0.0.1:${port}/meta` });
      assert.ok(result.kind === "success");
      assert.equal(result.body, undefined);
      assert.match(result.bodyWithheldReason ?? "", /metadata only/u);
    },
  );
});

void test("an unexpected content type withholds the body", async () => {
  await withUpstream(
    (_req, res) => {
      res.setHeader("content-type", "text/html");
      res.end("<html>surprise</html>");
    },
    async (port) => {
      const { engine } = makeEngine(port);
      const result = await engine.execute({ credentialId: "local", method: "GET", url: `http://127.0.0.1:${port}/data` });
      assert.ok(result.kind === "success");
      assert.equal(result.body, undefined);
      assert.match(result.bodyWithheldReason ?? "", /not in this operation's/u);
    },
  );
});

void test("redirects are refused and never followed with the credential", async () => {
  await withUpstream(
    (_req, res) => {
      res.statusCode = 302;
      res.setHeader("location", "https://evil.example.com/");
      res.end();
    },
    async (port) => {
      const { engine } = makeEngine(port);
      const result = await engine.execute({ credentialId: "local", method: "GET", url: `http://127.0.0.1:${port}/hop` });
      assert.equal(result.kind, "error");
    },
  );
});

// ---------------------------------------------------------------------------
// Issue #4: principal-scoped secrets and engine-only execution
// ---------------------------------------------------------------------------

void test("secrets for credentials granted to other agents are never even loaded", async () => {
  const { engine, secrets } = makeEngine(9999);
  assert.equal(secrets.getSecret("foreign"), undefined, "provider must not hold another agent's secret");
  assert.ok(!secrets.listSecretValues().includes(OTHER_SECRET));
  const result = await engine.execute({ credentialId: "foreign", method: "GET", url: "http://127.0.0.1:9999/x" });
  assert.equal(result.kind, "denied");
  assert.ok(result.kind === "denied");
  assert.equal(result.decidingRule?.source, "credential-not-granted");
});

void test("scrubEnv removes every policy credential variable from the environment", () => {
  const env: Record<string, string | undefined> = {
    BROKER_TEST_SECRET: SECRET,
    BROKER_TEST_BASIC: SECRET,
    BROKER_TEST_QUERY: SECRET,
    BROKER_TEST_FOREIGN: OTHER_SECRET,
    UNRELATED: "stays",
  };
  const policy = policyFor(8080);
  const provider = new EnvSecretProvider(policy, "tester", { env, scrubEnv: true });
  assert.equal(env.BROKER_TEST_SECRET, undefined);
  assert.equal(env.BROKER_TEST_FOREIGN, undefined, "ungranted secrets are scrubbed too");
  assert.equal(env.UNRELATED, "stays");
  assert.equal(provider.getSecret("local"), SECRET);
  assert.equal(provider.getSecret("foreign"), undefined);
});

void test("the engine refuses to construct for an unprovisioned principal", () => {
  const policy = policyFor(8080);
  assert.throws(
    () =>
      new BrokerEngine({
        policy,
        principalId: "ghost",
        secrets: new EnvSecretProvider(policy, "ghost", { env: {} }),
        audit: new MemoryAuditSink(),
      }),
    /not provisioned/u,
  );
});

void test("an unprovisioned credential fails closed without naming the env var to the agent", async () => {
  const { engine } = makeEngine(9999, { env: {} });
  const result = await engine.execute({ credentialId: "local", method: "GET", url: "http://127.0.0.1:9999/data" });
  assert.equal(result.kind, "error");
  assert.ok(result.kind === "error");
  assert.equal(result.code, "not-provisioned");
  assert.ok(!result.message.includes("BROKER_TEST_SECRET"), "env var names are operator detail, not agent detail");
});

// ---------------------------------------------------------------------------
// Issue #5: approval-aware execution, idempotency, audit lifecycle
// ---------------------------------------------------------------------------

const APPROVAL = {
  id: "apr-1",
  agentId: "tester",
  credentialId: "local",
  operationId: "delete-thing",
  expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
};

void test("a mutation behind approval is denied without one and allowed with a valid one", async () => {
  await withUpstream(
    (req, res) => {
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ deleted: req.url }));
    },
    async (port) => {
      const { engine, approvals } = makeEngine(port);
      const request = {
        credentialId: "local",
        method: "DELETE",
        url: `http://127.0.0.1:${port}/thing/42`,
        idempotencyKey: "idem-1",
      };
      const missing = await engine.execute(request);
      assert.equal(missing.kind, "denied");
      assert.ok(missing.kind === "denied");
      assert.match(missing.reason, /approval_id/u);

      approvals.put({ ...APPROVAL });
      const approved = await engine.execute({ ...request, approvalId: "apr-1" });
      assert.equal(approved.kind, "success");
    },
  );
});

void test("approval expiry is checked at execution time with the injected clock", async () => {
  let upstreamCalls = 0;
  await withUpstream(
    (_req, res) => {
      upstreamCalls += 1;
      res.end("{}");
    },
    async (port) => {
      let nowMs = Date.now();
      const clock: Clock = { now: () => new Date(nowMs) };
      const { engine, approvals } = makeEngine(port, { clock });
      approvals.put({ ...APPROVAL, expiresAt: new Date(nowMs + 1_000).toISOString() });

      // Preflight says the approval is currently satisfied.
      const preflight = await engine.explain({
        credentialId: "local",
        method: "DELETE",
        url: `http://127.0.0.1:${port}/thing/42`,
        approvalId: "apr-1",
      });
      assert.equal(preflight.approvalState, "satisfied");

      // Time passes between preflight and execution; the approval expires.
      nowMs += 5_000;
      const result = await engine.execute({
        credentialId: "local",
        method: "DELETE",
        url: `http://127.0.0.1:${port}/thing/42`,
        approvalId: "apr-1",
        idempotencyKey: "idem-2",
      });
      assert.equal(result.kind, "denied");
      assert.ok(result.kind === "denied");
      assert.match(result.reason, /expired/u);
      assert.equal(upstreamCalls, 0, "an expired approval must stop the request before any upstream call");
    },
  );
});

void test("revocation between preflight and execution denies the mutation", async () => {
  let upstreamCalls = 0;
  await withUpstream(
    (_req, res) => {
      upstreamCalls += 1;
      res.end("{}");
    },
    async (port) => {
      const { engine, approvals } = makeEngine(port);
      approvals.put({ ...APPROVAL });
      const preflight = await engine.explain({
        credentialId: "local",
        method: "DELETE",
        url: `http://127.0.0.1:${port}/thing/42`,
        approvalId: "apr-1",
      });
      assert.equal(preflight.approvalState, "satisfied");

      approvals.revoke("apr-1");
      const result = await engine.execute({
        credentialId: "local",
        method: "DELETE",
        url: `http://127.0.0.1:${port}/thing/42`,
        approvalId: "apr-1",
        idempotencyKey: "idem-3",
      });
      assert.equal(result.kind, "denied");
      assert.ok(result.kind === "denied");
      assert.match(result.reason, /revoked/u);
      assert.equal(upstreamCalls, 0);
    },
  );
});

void test("approvals are bound to principal, credential, and operation", async () => {
  const { engine, approvals } = makeEngine(9999);
  approvals.put({ ...APPROVAL, operationId: "some-other-operation" });
  const result = await engine.execute({
    credentialId: "local",
    method: "DELETE",
    url: "http://127.0.0.1:9999/thing/42",
    approvalId: "apr-1",
    idempotencyKey: "idem-4",
  });
  assert.equal(result.kind, "denied");
  assert.ok(result.kind === "denied");
  assert.match(result.reason, /not transferable/u);
});

void test("a required idempotency key is enforced and audited", async () => {
  const { engine, audit, approvals } = makeEngine(9999);
  approvals.put({ ...APPROVAL });
  const result = await engine.execute({
    credentialId: "local",
    method: "DELETE",
    url: "http://127.0.0.1:9999/thing/42",
    approvalId: "apr-1",
  });
  assert.equal(result.kind, "denied");
  assert.ok(result.kind === "denied");
  assert.match(result.reason, /idempotency_key/u);
  assert.ok(audit.records.some((record) => record.outcome === "denied"));
});

void test("the audit lifecycle runs requested, approved, executing, succeeded with one trace id", async () => {
  await withUpstream(
    (_req, res) => {
      res.setHeader("content-type", "application/json");
      res.end("{}");
    },
    async (port) => {
      const { engine, audit, approvals } = makeEngine(port);
      approvals.put({ ...APPROVAL });
      const result = await engine.execute({
        credentialId: "local",
        method: "DELETE",
        url: `http://127.0.0.1:${port}/thing/42`,
        approvalId: "apr-1",
        idempotencyKey: "idem-5",
      });
      assert.equal(result.kind, "success");
      const outcomes = audit.records.map((record) => record.outcome);
      assert.deepEqual(outcomes, ["requested", "approved", "executing", "succeeded"]);
      const traceIds = new Set(audit.records.map((record) => record.traceId));
      assert.equal(traceIds.size, 1);
      assert.equal(audit.records[0]?.operationId, "delete-thing");
      assert.equal(audit.records[0]?.idempotencyKey, "idem-5");
    },
  );
});

void test("a mutation dispatch failure is recorded as indeterminate", async () => {
  const { engine, audit, approvals } = makeEngine(1);
  approvals.put({ ...APPROVAL });
  const result = await engine.execute({
    credentialId: "local",
    method: "DELETE",
    url: "http://127.0.0.1:1/thing/42",
    approvalId: "apr-1",
    idempotencyKey: "idem-6",
  });
  assert.equal(result.kind, "error");
  assert.ok(result.kind === "error");
  assert.equal(result.outcome, "indeterminate");
  assert.match(result.message, /may or may not have been applied/u);
  assert.equal(audit.records.at(-1)?.outcome, "indeterminate");
});

void test("a denied evaluation performs no upstream call", async () => {
  let upstreamCalls = 0;
  await withUpstream(
    (_req, res) => {
      upstreamCalls += 1;
      res.end("ok");
    },
    async (port) => {
      const { engine, audit } = makeEngine(port);
      const result = await engine.execute({
        credentialId: "local",
        method: "GET",
        url: `http://127.0.0.1:${port}/admin/panel`,
      });
      assert.equal(result.kind, "denied");
      assert.equal(upstreamCalls, 0);
      assert.deepEqual(
        audit.records.map((record) => record.outcome),
        ["requested", "denied"],
      );
    },
  );
});

void test("POST with an allowed body executes; the body rule is enforced", async () => {
  await withUpstream(
    (req, res) => {
      let data = "";
      req.on("data", (chunk: Buffer) => (data += chunk.toString("utf8")));
      req.on("end", () => {
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({ received: data }));
      });
    },
    async (port) => {
      const { engine } = makeEngine(port);
      const ok = await engine.execute({
        credentialId: "local",
        method: "POST",
        url: `http://127.0.0.1:${port}/echo`,
        body: JSON.stringify({ hello: "world" }),
        contentType: "application/json",
      });
      assert.equal(ok.kind, "success");

      const wrongType = await engine.execute({
        credentialId: "local",
        method: "POST",
        url: `http://127.0.0.1:${port}/echo`,
        body: "hello=world",
        contentType: "application/x-www-form-urlencoded",
      });
      assert.equal(wrongType.kind, "denied");

      const tooBig = await engine.execute({
        credentialId: "local",
        method: "POST",
        url: `http://127.0.0.1:${port}/echo`,
        body: JSON.stringify({ pad: "x".repeat(2_000) }),
        contentType: "application/json",
      });
      assert.equal(tooBig.kind, "denied");
    },
  );
});
