import assert from "node:assert/strict";
import test from "node:test";

import { loadPrincipalSecrets } from "../src/engine.js";
import { addCredentialToPolicy, envVarFor } from "../src/policy-edit.js";
import { parseBrokerPolicy } from "../src/policy.js";

const BASE = `# operator comment that must survive
version: 2
credentials:
  - id: github
    kind: bearer
    env_var: GITHUB_TOKEN
    base_url: https://api.github.com
agents:
  - id: claude
    grants:
      - credential: github
        operations:
          - id: read-repo
            method: GET
            path: /repos/*/*
`;

void test("adds a credential with a read grant to an existing agent and keeps comments", () => {
  const text = addCredentialToPolicy(BASE, {
    id: "openai",
    description: "OpenAI",
    kind: "bearer",
    baseUrl: "https://api.openai.com/v1",
    grant: { agentId: "claude", queryParams: ["limit"] },
  });
  assert.match(text, /# operator comment that must survive/u);
  const policy = parseBrokerPolicy(text);
  const credential = policy.credentials.get("openai");
  assert.equal(credential?.envVar, "CB_OPENAI");
  const grant = policy.agents.get("claude")?.grants.get("openai");
  assert.equal(grant?.operations.length, 1);
  assert.equal(grant?.operations[0]?.method, "GET");
  assert.deepEqual(grant?.operations[0]?.pathTemplate, ["**"]);
  assert.deepEqual(grant?.operations[0]?.queryParams, ["limit"]);
  // Nothing about the existing grant changed.
  assert.equal(policy.agents.get("claude")?.grants.get("github")?.operations[0]?.id, "read-repo");
});

void test("creates a starter policy and a new agent when no file exists", () => {
  const text = addCredentialToPolicy(null, {
    id: "weather",
    description: "",
    kind: "query",
    paramName: "appid",
    baseUrl: "https://api.openweathermap.org/data/2.5",
    grant: { agentId: "claude", displayName: "Claude Code", queryParams: [] },
  });
  const policy = parseBrokerPolicy(text);
  assert.equal(policy.credentials.get("weather")?.highRisk, true);
  assert.equal(policy.agents.get("claude")?.displayName, "Claude Code");
});

void test("only ever grants GET", () => {
  const text = addCredentialToPolicy(BASE, {
    id: "stripe",
    description: "",
    kind: "basic",
    baseUrl: "https://api.stripe.com",
    grant: { agentId: "claude", queryParams: [] },
  });
  const operations = parseBrokerPolicy(text).agents.get("claude")?.grants.get("stripe")?.operations ?? [];
  assert.ok(operations.every((op) => op.method === "GET"));
});

void test("refuses duplicates and policies the broker would refuse", () => {
  assert.throws(
    () => addCredentialToPolicy(BASE, { id: "github", description: "", kind: "bearer", baseUrl: "https://api.github.com", grant: null }),
    /already exists/u,
  );
  assert.throws(
    () => addCredentialToPolicy(BASE, { id: "plain", description: "", kind: "bearer", baseUrl: "http://example.com", grant: null }),
    /https/u,
  );
  assert.throws(
    () => addCredentialToPolicy(null, { id: "lonely", description: "", kind: "bearer", baseUrl: "https://example.com", grant: null }),
    /at least one agent/u,
  );
});

void test("env var names are derived from ids", () => {
  assert.equal(envVarFor("my-api.v2"), "CB_MY_API_V2");
});

void test("secrets: environment wins, keychain fills gaps, only granted ids are requested", async () => {
  const policy = parseBrokerPolicy(
    addCredentialToPolicy(
      addCredentialToPolicy(BASE, {
        id: "openai",
        description: "",
        kind: "bearer",
        baseUrl: "https://api.openai.com/v1",
        grant: { agentId: "claude", queryParams: [] },
      }),
      { id: "other", description: "", kind: "bearer", baseUrl: "https://example.com", grant: { agentId: "someone-else", queryParams: [] } },
    ),
  );
  const requested: string[][] = [];
  const keychain = {
    getMany(ids: readonly string[]) {
      requested.push([...ids]);
      return Promise.resolve(new Map(ids.map((id) => [id, `kc-${id}`])));
    },
  };
  const env: Record<string, string | undefined> = { GITHUB_TOKEN: "env-github", CB_OTHER: "env-other" };
  const secrets = await loadPrincipalSecrets(policy, "claude", { env, scrubEnv: true, keychain });

  assert.equal(secrets.getSecret("github"), "env-github");
  assert.equal(secrets.getSecret("openai"), "kc-openai");
  assert.equal(secrets.getSecret("other"), undefined);
  assert.deepEqual(requested, [["openai"]]);
  assert.deepEqual(secrets.listSecretValues().sort(), ["env-github", "kc-openai"]);
  // Every policy credential variable is scrubbed, granted or not.
  assert.equal(env.GITHUB_TOKEN, undefined);
  assert.equal(env.CB_OTHER, undefined);
});

void test("secrets: no keychain means environment only", async () => {
  const policy = parseBrokerPolicy(BASE);
  const secrets = await loadPrincipalSecrets(policy, "claude", { env: {}, keychain: null });
  assert.equal(secrets.getSecret("github"), undefined);
});
