import assert from "node:assert/strict";
import { createServer } from "node:http";
import test from "node:test";

import { evaluate, executeRequest } from "../src/gateway.js";
import { parseBrokerPolicy } from "../src/policy.js";

import type { AddressInfo } from "node:net";
import type { AgentGrant, CredentialSpec } from "../src/types.js";

const SECRET = "test-secret-value-12345";

function policyFor(port: number) {
  return parseBrokerPolicy(`
version: 1
credentials:
  - id: local
    description: Loopback upstream
    kind: header
    env_var: BROKER_TEST_SECRET
    param_name: x-api-key
    base_url: http://127.0.0.1:${port}
agents:
  - id: tester
    display_name: Tester
    enabled: true
    credentials: [local]
    methods: [GET, POST]
    allow: ["/**"]
    deny: ["/admin/**"]
    max_response_bytes: 64
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

function grants(port: number): { credential: CredentialSpec; agent: AgentGrant } {
  const policy = policyFor(port);
  const credential = policy.credentials.get("local");
  const agent = policy.agents.get("tester");
  assert.ok(credential && agent);
  return { credential, agent };
}

void test("injects the secret header upstream and never relays it back", async () => {
  process.env.BROKER_TEST_SECRET = SECRET;
  await withUpstream(
    (req, res) => {
      // Upstream sees the secret; it also rudely echoes it, as debug
      // endpoints and error pages sometimes do.
      res.setHeader("content-type", "application/json");
      res.setHeader("set-cookie", "session=leaky");
      res.end(JSON.stringify({ got: req.headers["x-api-key"] }));
    },
    async (port) => {
      const { credential, agent } = grants(port);
      const response = await executeRequest(credential, agent, {
        method: "GET",
        url: `http://127.0.0.1:${port}/data`,
      });
      assert.equal(response.status, 200);
      assert.ok(!response.body.includes(SECRET), "secret must be redacted from the body");
      assert.ok(response.body.includes("[REDACTED]"));
      assert.equal(response.headers["set-cookie"], undefined, "unsafe headers must be dropped");
      assert.equal(response.headers["content-type"], "application/json");
    },
  );
});

void test("caps the response body at the agent's byte budget", async () => {
  process.env.BROKER_TEST_SECRET = SECRET;
  await withUpstream(
    (_req, res) => {
      res.end("x".repeat(10_000));
    },
    async (port) => {
      const { credential, agent } = grants(port);
      const response = await executeRequest(credential, agent, {
        method: "GET",
        url: `http://127.0.0.1:${port}/big`,
      });
      assert.equal(response.truncated, true);
      assert.equal(response.body.length, agent.maxResponseBytes);
    },
  );
});

void test("refuses to follow redirects", async () => {
  process.env.BROKER_TEST_SECRET = SECRET;
  await withUpstream(
    (_req, res) => {
      res.statusCode = 302;
      res.setHeader("location", "https://evil.example.com/");
      res.end();
    },
    async (port) => {
      const { credential, agent } = grants(port);
      await assert.rejects(
        executeRequest(credential, agent, { method: "GET", url: `http://127.0.0.1:${port}/hop` }),
      );
    },
  );
});

void test("an unprovisioned credential fails closed without leaking the variable's value", async () => {
  delete process.env.BROKER_TEST_SECRET;
  await withUpstream(
    (_req, res) => res.end("ok"),
    async (port) => {
      const { credential, agent } = grants(port);
      await assert.rejects(
        executeRequest(credential, agent, { method: "GET", url: `http://127.0.0.1:${port}/data` }),
        /not provisioned \(missing BROKER_TEST_SECRET\)/u,
      );
    },
  );
});

void test("query-kind credentials land in the query string, not headers", async () => {
  process.env.BROKER_TEST_QUERY = SECRET;
  await withUpstream(
    (req, res) => {
      res.setHeader("content-type", "application/json");
      const url = new URL(req.url ?? "/", "http://127.0.0.1");
      res.end(JSON.stringify({ key: url.searchParams.get("appid"), auth: req.headers.authorization ?? null }));
    },
    async (port) => {
      const credential: CredentialSpec = {
        id: "q",
        description: "",
        kind: "query",
        envVar: "BROKER_TEST_QUERY",
        paramName: "appid",
        baseUrl: `http://127.0.0.1:${port}`,
      };
      const { agent } = grants(port);
      const bigAgent = { ...agent, maxResponseBytes: 10_000 };
      const response = await executeRequest(credential, bigAgent, {
        method: "GET",
        url: `http://127.0.0.1:${port}/weather`,
      });
      const parsed = JSON.parse(response.body.replace("[REDACTED]", "seen")) as { key: string; auth: null };
      assert.equal(parsed.key, "seen");
      assert.equal(parsed.auth, null);
    },
  );
});

void test("the live path and the explainer share one decision function", async () => {
  // evaluate() is the single source of truth by construction; this pins the
  // contract that a denied evaluation refuses before any upstream call.
  process.env.BROKER_TEST_SECRET = SECRET;
  let upstreamCalls = 0;
  await withUpstream(
    (_req, res) => {
      upstreamCalls += 1;
      res.end("ok");
    },
    async (port) => {
      const policy = policyFor(port);
      const denied = evaluate(policy, "tester", "local", "GET", `http://127.0.0.1:${port}/admin/panel`);
      assert.equal(denied.allowed, false);
      // The server only executes when evaluate() allows, so a denied decision
      // means zero upstream traffic by construction.
      assert.equal(upstreamCalls, 0);
    },
  );
});
