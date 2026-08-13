import assert from "node:assert/strict";
import test from "node:test";

import { evaluate } from "../src/gateway.js";
import { migrateV1PolicyText } from "../src/migrate.js";
import { parseBrokerPolicy } from "../src/policy.js";

export const policyFixture = `
version: 2
credentials:
  - id: github
    description: GitHub API
    kind: bearer
    env_var: TEST_GITHUB_TOKEN
    base_url: https://api.github.com
  - id: weather
    description: Weather API with a base path
    kind: query
    env_var: TEST_WEATHER_KEY
    param_name: appid
    base_url: https://api.openweathermap.org/data/2.5
    high_risk: true
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
    grants:
      - credential: github
        operations:
          - id: read-repo
            method: GET
            path: /repos/*/*
            response_body: true
          - id: read-repo-tree
            method: GET
            path: /repos/*/*/contents/**
            query_params: [ref]
            response_body: true
        deny:
          - /repos/*/*/keys
          - /admin/**
      - credential: weather
        operations:
          - id: current-weather
            method: GET
            path: /weather
            query_params: [q, units]
            response_body: true
  - id: writer
    display_name: Writer
    enabled: true
    grants:
      - credential: github
        operations:
          - id: read-org-repo
            method: GET
            path: /repos/org/*
            response_body: true
          - id: delete-org-repo
            method: DELETE
            path: /repos/org/*
            requires_approval: true
  - id: disabled-agent
    display_name: Disabled
    enabled: false
    grants:
      - credential: github
        operations:
          - id: read-anything
            method: GET
            path: /**
`;

function fixture() {
  return parseBrokerPolicy(policyFixture);
}

void test("parses a valid v2 policy and normalises base URLs", () => {
  const policy = fixture();
  const github = policy.credentials.get("github");
  assert.equal(github?.origin, "https://api.github.com");
  assert.deepEqual(github?.basePathSegments, []);
  const weather = policy.credentials.get("weather");
  assert.equal(weather?.origin, "https://api.openweathermap.org");
  assert.deepEqual(weather?.basePathSegments, ["data", "2.5"]);
});

void test("policy version 1 is refused with migration guidance", () => {
  const v1 = `
version: 1
credentials:
  - id: github
    kind: bearer
    env_var: T
    base_url: https://api.github.com
agents:
  - id: a
    credentials: [github]
    methods: [GET]
    allow: ["/repos/**"]
`;
  assert.throws(() => parseBrokerPolicy(v1), /version 1 is no longer supported/u);
  assert.throws(() => parseBrokerPolicy(v1), /migrate/iu);
});

void test("query-string credentials must be acknowledged as high risk", () => {
  assert.throws(
    () => parseBrokerPolicy(policyFixture.replace("high_risk: true", "high_risk: false")),
    /high_risk/u,
  );
});

void test("mutations must state requires_approval explicitly", () => {
  const broken = policyFixture.replace("            requires_approval: true\n", "");
  assert.throws(() => parseBrokerPolicy(broken), /requires_approval explicitly/u);
});

void test("read operations must not declare a request body", () => {
  const broken = policyFixture.replace(
    "          - id: current-weather\n            method: GET\n            path: /weather",
    "          - id: current-weather\n            method: GET\n            path: /weather\n            body: {content_types: [application/json], max_bytes: 10}",
  );
  assert.throws(() => parseBrokerPolicy(broken), /must not declare a request body/u);
});

void test("rejects plain-http credentials except on loopback", () => {
  assert.throws(
    () => parseBrokerPolicy(policyFixture.replace("https://api.github.com", "http://api.github.com")),
    /must use https/u,
  );
  assert.ok(fixture().credentials.has("local-service"));
});

void test("rejects unknown credential references, duplicates, and bad templates", () => {
  assert.throws(
    () => parseBrokerPolicy(policyFixture.replace("- credential: weather", "- credential: missing")),
    /unknown credential/u,
  );
  assert.throws(
    () => parseBrokerPolicy(policyFixture.replace("path: /weather", "path: /a/**/b")),
    /final segment/u,
  );
  assert.throws(
    () => parseBrokerPolicy(policyFixture.replace("id: read-repo-tree", "id: read-repo")),
    /duplicate operation id/u,
  );
});

// ---------------------------------------------------------------------------
// Per-credential capability isolation (issue #2)
// ---------------------------------------------------------------------------

void test("a method granted on one credential never widens another credential", () => {
  const policy = fixture();
  // writer holds DELETE on github (behind approval, which the engine
  // enforces at execution time). Policy evaluation matches the operation.
  const writerDelete = evaluate(policy, "writer", "github", {
    method: "DELETE",
    url: "https://api.github.com/repos/org/thing",
  });
  assert.equal(writerDelete.allowed, true);
  assert.equal(writerDelete.operation?.id, "delete-org-repo");
  assert.equal(writerDelete.operation?.requiresApproval, true);

  const crossCredential = evaluate(policy, "reader", "weather", {
    method: "DELETE",
    url: "https://api.openweathermap.org/data/2.5/weather",
  });
  assert.equal(crossCredential.allowed, false);
  assert.equal(crossCredential.decidingRule?.source, "method-not-allowed");

  const crossAgent = evaluate(policy, "reader", "github", {
    method: "DELETE",
    url: "https://api.github.com/repos/org/thing",
  });
  assert.equal(crossAgent.allowed, false);
  assert.equal(crossAgent.decidingRule?.source, "method-not-allowed");
});

void test("the github/weather example routes correctly with base-relative paths", () => {
  const policy = fixture();
  // Intended weather request succeeds against the weather credential.
  const weather = evaluate(policy, "reader", "weather", {
    method: "GET",
    url: "https://api.openweathermap.org/data/2.5/weather?q=London&units=metric",
  });
  assert.equal(weather.allowed, true);
  assert.equal(weather.operation?.id, "current-weather");
  // /weather on the GitHub credential is a cross-credential route: denied.
  const bleed = evaluate(policy, "reader", "github", {
    method: "GET",
    url: "https://api.github.com/weather",
  });
  assert.equal(bleed.allowed, false);
  // GitHub paths through the weather credential are outside its base.
  const reverse = evaluate(policy, "reader", "weather", {
    method: "GET",
    url: "https://api.openweathermap.org/repos/a/b",
  });
  assert.equal(reverse.allowed, false);
  assert.equal(reverse.decidingRule?.source, "url-outside-base");
});

void test("base path matching is segment-wise, not a string prefix", () => {
  const policy = fixture();
  const decision = evaluate(policy, "reader", "weather", {
    method: "GET",
    url: "https://api.openweathermap.org/data/2.5extra/weather",
  });
  assert.equal(decision.allowed, false);
  assert.equal(decision.decidingRule?.source, "url-outside-base");
});

void test("unlisted query parameters are denied", () => {
  const policy = fixture();
  const decision = evaluate(policy, "reader", "weather", {
    method: "GET",
    url: "https://api.openweathermap.org/data/2.5/weather?q=London&appid=sneaky",
  });
  assert.equal(decision.allowed, false);
  assert.equal(decision.decidingRule?.source, "query-param-not-allowed");
  assert.equal(decision.decidingRule?.pattern, "appid");
});

void test("bodies are rejected unless the operation declares a body rule", () => {
  const policy = fixture();
  const decision = evaluate(policy, "writer", "github", {
    method: "DELETE",
    url: "https://api.github.com/repos/org/thing",
    body: "{}",
    contentType: "application/json",
  });
  assert.equal(decision.allowed, false);
  assert.equal(decision.decidingRule?.source, "body-not-allowed");
});

// ---------------------------------------------------------------------------
// Encoded/ambiguous path bypass regressions (issue #1)
// ---------------------------------------------------------------------------

void test("percent-encoded representations of a denied path are denied", () => {
  const policy = fixture();
  const literal = evaluate(policy, "reader", "github", {
    method: "GET",
    url: "https://api.github.com/repos/a/b/keys",
  });
  assert.equal(literal.allowed, false);
  assert.equal(literal.decidingRule?.source, "grant-deny");

  // The audit's original probe: %61 == 'a'. Canonicalisation decodes it, so
  // the deny rule sees the same form the upstream would.
  const encoded = evaluate(policy, "reader", "github", {
    method: "GET",
    url: "https://api.github.com/repos/%61/b/keys",
  });
  assert.equal(encoded.allowed, false);
  assert.equal(encoded.decidingRule?.source, "grant-deny");

  const admin = evaluate(policy, "reader", "github", {
    method: "GET",
    url: "https://api.github.com/%61dmin/panel",
  });
  assert.equal(admin.allowed, false);
  assert.equal(admin.decidingRule?.source, "grant-deny");
});

void test("deny rules are evaluated case-insensitively; allows are case-sensitive", () => {
  const policy = fixture();
  const denyMixedCase = evaluate(policy, "reader", "github", {
    method: "GET",
    url: "https://api.github.com/Admin/panel",
  });
  assert.equal(denyMixedCase.allowed, false);
  assert.equal(denyMixedCase.decidingRule?.source, "grant-deny");

  const allowMixedCase = evaluate(policy, "reader", "github", {
    method: "GET",
    url: "https://api.github.com/Repos/a/b",
  });
  assert.equal(allowMixedCase.allowed, false, "allow templates must not match a different case");
});

void test("ambiguous representations are rejected, not guessed at", () => {
  const policy = fixture();
  const cases = [
    "https://api.github.com/repos/a%2Fb/keys",
    "https://api.github.com/repos/a%5Cb/c",
    "https://api.github.com/repos/a/b/%252e%252e",
    "https://api.github.com//repos/a/b",
    "https://api.github.com/repos/a/b/keys%20",
    "https://api.github.com/repos/a/b/keys.",
  ];
  for (const url of cases) {
    const decision = evaluate(policy, "reader", "github", { method: "GET", url });
    assert.equal(decision.allowed, false, `must reject '${url}'`);
    assert.equal(decision.decidingRule?.source, "url-invalid", `'${url}' should fail canonicalisation`);
  }
  // Encoded dot segments are resolved by the parser to their canonical form,
  // then policy decides on that form. /repos/%2e%2e/x collapses to /x.
  const collapsed = evaluate(policy, "reader", "github", {
    method: "GET",
    url: "https://api.github.com/repos/%2e%2e/repos/a/b/keys",
  });
  assert.equal(collapsed.allowed, false);
  assert.equal(collapsed.decidingRule?.source, "grant-deny", "the collapsed form must hit the deny rule");
});

void test("origin must match exactly; lookalike and prefix-sharing hosts are refused", () => {
  const policy = fixture();
  for (const url of [
    "https://evil.example.com/repos/a/b",
    "https://api.github.com.evil.example/repos/a/b",
    "https://api-github.com/repos/a/b",
    "http://api.github.com/repos/a/b",
    "https://api.github.com:8443/repos/a/b",
  ]) {
    const decision = evaluate(policy, "reader", "github", { method: "GET", url });
    assert.equal(decision.allowed, false, `must refuse '${url}'`);
    assert.equal(decision.decidingRule?.source, "url-outside-base");
  }
});

void test("identity gates still produce specific reasons", () => {
  const policy = fixture();
  const ungranted = evaluate(policy, "reader", "local-service", {
    method: "GET",
    url: "http://127.0.0.1:8080/thing",
  });
  assert.equal(ungranted.decidingRule?.source, "credential-not-granted");

  const disabled = evaluate(policy, "disabled-agent", "github", {
    method: "GET",
    url: "https://api.github.com/repos/a/b",
  });
  assert.equal(disabled.decidingRule?.source, "agent-disabled");

  const unknown = evaluate(policy, "ghost", "github", {
    method: "GET",
    url: "https://api.github.com/repos/a/b",
  });
  assert.equal(unknown.allowed, false);
});

void test("absent operation is deny-by-default with the canonical path named", () => {
  const policy = fixture();
  const decision = evaluate(policy, "reader", "github", {
    method: "GET",
    url: "https://api.github.com/user",
  });
  assert.equal(decision.allowed, false);
  assert.equal(decision.decidingRule?.source, "no-operation");
  assert.match(decision.reason, /deny-by-default/u);
});

void test("an allowed request names the deciding operation", () => {
  const policy = fixture();
  const decision = evaluate(policy, "reader", "github", {
    method: "GET",
    url: "https://api.github.com/repos/a/b",
  });
  assert.equal(decision.allowed, true);
  assert.equal(decision.decidingRule?.source, "operation-allow");
  assert.equal(decision.decidingRule?.pattern, "read-repo");
});

// ---------------------------------------------------------------------------
// v1 migration (issue #2)
// ---------------------------------------------------------------------------

void test("migrateV1PolicyText produces a parseable, conservative v2 policy", () => {
  const v1 = `
version: 1
credentials:
  - id: github
    kind: bearer
    env_var: TEST_GITHUB_TOKEN
    base_url: https://api.github.com
  - id: weather
    kind: query
    env_var: TEST_WEATHER_KEY
    param_name: appid
    base_url: https://api.openweathermap.org/data/2.5
agents:
  - id: researcher
    credentials: [github, weather]
    methods: [GET, POST]
    allow: ["/repos/*/*", "/weather"]
    deny: ["/repos/*/*/keys"]
`;
  const migrated = migrateV1PolicyText(v1);
  assert.match(migrated, /REVIEW BEFORE USE/u);
  const policy = parseBrokerPolicy(migrated);
  const agent = policy.agents.get("researcher");
  assert.ok(agent);
  // The expansion is per credential, and every mutation requires approval.
  for (const grant of agent.grants.values()) {
    for (const operation of grant.operations) {
      if (operation.method === "POST") assert.equal(operation.requiresApproval, true);
      assert.deepEqual(operation.queryParams, []);
    }
  }
  // Query credential acknowledged as high risk in the migration output.
  assert.equal(policy.credentials.get("weather")?.highRisk, true);
});

void test("migration refuses glob syntax it cannot prove equivalent", () => {
  const v1 = `
version: 1
credentials:
  - id: github
    kind: bearer
    env_var: T
    base_url: https://api.github.com
agents:
  - id: a
    credentials: [github]
    methods: [GET]
    allow: ["/repos/{a,b}/**"]
`;
  assert.throws(() => migrateV1PolicyText(v1), /glob syntax beyond/u);
});
