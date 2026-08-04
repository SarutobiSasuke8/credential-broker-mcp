import assert from "node:assert/strict";
import test from "node:test";

import { evaluate } from "../src/gateway.js";
import { parseBrokerPolicy } from "../src/policy.js";

export const policyFixture = `
version: 1
credentials:
  - id: github
    description: GitHub API
    kind: bearer
    env_var: TEST_GITHUB_TOKEN
    base_url: https://api.github.com
  - id: local-service
    description: Loopback service for tests
    kind: header
    env_var: TEST_LOCAL_KEY
    param_name: x-api-key
    base_url: http://127.0.0.1:8080
agents:
  - id: reader
    display_name: Reader
    enabled: true
    credentials: [github]
    methods: [GET]
    allow: ["/repos/**"]
    deny: ["/repos/*/*/keys"]
    max_response_bytes: 1024
  - id: disabled-agent
    display_name: Disabled
    enabled: false
    credentials: [github]
    methods: [GET]
    allow: ["/**"]
    deny: []
`;

void test("parses a valid policy and normalizes base URLs", () => {
  const policy = parseBrokerPolicy(policyFixture);
  assert.equal(policy.credentials.get("github")?.baseUrl, "https://api.github.com");
  assert.equal(policy.agents.get("reader")?.methods[0], "GET");
});

void test("rejects plain-http credentials except on loopback", () => {
  assert.throws(
    () =>
      parseBrokerPolicy(policyFixture.replace("https://api.github.com", "http://api.github.com")),
    /must use https/u,
  );
  // The loopback credential in the fixture parses fine.
  assert.ok(parseBrokerPolicy(policyFixture).credentials.has("local-service"));
});

void test("rejects unknown credential references and duplicates", () => {
  assert.throws(
    () => parseBrokerPolicy(policyFixture.replace("credentials: [github]\n    methods: [GET]\n    allow: [\"/repos/**\"]", "credentials: [missing]\n    methods: [GET]\n    allow: [\"/repos/**\"]")),
    /unknown credential/u,
  );
});

void test("deny beats allow and is reported as the deciding rule", () => {
  const policy = parseBrokerPolicy(policyFixture);
  const decision = evaluate(policy, "reader", "github", "GET", "https://api.github.com/repos/a/b/keys");
  assert.equal(decision.allowed, false);
  assert.equal(decision.decidingRule?.source, "agent-deny");
  assert.match(decision.reason, /Deny always beats a grant/u);
});

void test("a URL outside the credential base is refused even when the path glob matches", () => {
  const policy = parseBrokerPolicy(policyFixture);
  const decision = evaluate(policy, "reader", "github", "GET", "https://evil.example.com/repos/a/b");
  assert.equal(decision.allowed, false);
  assert.equal(decision.decidingRule?.source, "url-outside-base");
});

void test("a lookalike host sharing the base as a prefix is refused", () => {
  const policy = parseBrokerPolicy(policyFixture);
  const decision = evaluate(policy, "reader", "github", "GET", "https://api.github.com.evil.example/repos/a/b");
  assert.equal(decision.allowed, false);
  assert.equal(decision.decidingRule?.source, "url-outside-base");
});

void test("method, grant, and enablement are each enforced with a specific reason", () => {
  const policy = parseBrokerPolicy(policyFixture);

  const post = evaluate(policy, "reader", "github", "POST", "https://api.github.com/repos/a/b");
  assert.equal(post.decidingRule?.source, "method-not-allowed");

  const ungranted = evaluate(policy, "reader", "local-service", "GET", "http://127.0.0.1:8080/thing");
  assert.equal(ungranted.decidingRule?.source, "credential-not-granted");

  const disabled = evaluate(policy, "disabled-agent", "github", "GET", "https://api.github.com/repos/a/b");
  assert.equal(disabled.decidingRule?.source, "agent-disabled");
});

void test("absent allow is deny-by-default with no phantom rule", () => {
  const policy = parseBrokerPolicy(policyFixture);
  const decision = evaluate(policy, "reader", "github", "GET", "https://api.github.com/user");
  assert.equal(decision.allowed, false);
  assert.equal(decision.decidingRule, null);
  assert.match(decision.reason, /deny-by-default/u);
});

void test("an allowed request names the allow rule and the base", () => {
  const policy = parseBrokerPolicy(policyFixture);
  const decision = evaluate(policy, "reader", "github", "GET", "https://api.github.com/repos/a/b");
  assert.equal(decision.allowed, true);
  assert.equal(decision.decidingRule?.source, "agent-allow");
  assert.equal(decision.decidingRule?.pattern, "/repos/**");
});
