import assert from "node:assert/strict";
import test from "node:test";

import { MemoryAuditSink } from "../src/audit.js";
import { BrokerEngine, MapSecretProvider } from "../src/engine.js";
import { parseBrokerPolicy } from "../src/policy.js";
import { revokedIdentityPolicy } from "../src/reload.js";

/** Fixes from the adversarial review that are not covered elsewhere. */

const POLICY = `
version: 2
credentials:
  - id: api
    kind: bearer
    env_var: T_API
    base_url: https://api.example.com
agents:
  - id: claude
    grants:
      - credential: api
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

function engine(audit: MemoryAuditSink, fetchImpl: () => Promise<Response>): BrokerEngine {
  return new BrokerEngine({
    policy: parseBrokerPolicy(POLICY),
    principalId: "claude",
    secrets: new MapSecretProvider(new Map([["api", "synthetic-secret-123456"]])),
    audit,
    fetchImpl,
  });
}

void test("a content type with control characters is denied before dispatch, with a terminal audit state", async () => {
  const audit = new MemoryAuditSink();
  let upstreamCalls = 0;
  const e = engine(audit, () => {
    upstreamCalls += 1;
    return Promise.resolve(new Response("{}", { status: 200, headers: { "content-type": "application/json" } }));
  });
  for (const contentType of ["text/plain\r\nx-injected: 1", "not a media type", "text/plain; charset=\u0007"]) {
    const result = await e.execute({ credentialId: "api", method: "GET", url: "https://api.example.com/things", contentType });
    assert.equal(result.kind, "denied", contentType);
  }
  assert.equal(upstreamCalls, 0);
  const outcomes = audit.records.map((r) => r.outcome);
  assert.ok(outcomes.every((o) => o === "requested" || o === "denied"), "nothing is left at executing");

  const fine = await e.execute({ credentialId: "api", method: "GET", url: "https://api.example.com/things", contentType: "application/json; charset=utf-8" });
  assert.equal(fine.kind, "success");
  assert.equal(upstreamCalls, 1);
});

void test("an identity removed from the policy during a reload is disabled with no grants, not kept on its old grants", () => {
  const previous = parseBrokerPolicy(POLICY);
  const without = parseBrokerPolicy(POLICY.replace(/ {2}- id: claude[\s\S]*?(?= {2}- id: codex)/u, ""));
  assert.equal(without.agents.has("claude"), false);
  const revoked = revokedIdentityPolicy(without, previous, "claude");
  const agent = revoked.agents.get("claude");
  assert.ok(agent);
  assert.equal(agent.enabled, false);
  assert.equal(agent.grants.size, 0);
  assert.ok(revoked.agents.get("codex")?.grants.has("api"), "other agents are untouched");
  const e = new BrokerEngine({ policy: revoked, principalId: "claude", secrets: new MapSecretProvider(new Map()), audit: new MemoryAuditSink() });
  return e.explain({ credentialId: "api", method: "GET", url: "https://api.example.com/things" }).then((explained) => {
    assert.equal(explained.allowed, false);
  });
});
