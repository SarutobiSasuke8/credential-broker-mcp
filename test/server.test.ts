import assert from "node:assert/strict";
import test from "node:test";

import { MemoryAuditSink } from "../src/audit.js";
import { EnvSecretProvider } from "../src/engine.js";
import { parseBrokerPolicy } from "../src/policy.js";
import { TOOL_CONTRACTS, createBrokerMcpServer } from "../src/server.js";

import { policyFixture } from "./policy.test.js";

const READ_METHODS = ["GET", "HEAD"];
const MUTATION_METHODS = ["POST", "PUT", "PATCH", "DELETE"];

void test("the read tool accepts only read methods and says so honestly", () => {
  const contract = TOOL_CONTRACTS.broker_read;
  assert.deepEqual([...contract.methods], READ_METHODS);
  assert.equal(contract.annotations.readOnlyHint, true);
  assert.equal(contract.annotations.destructiveHint, false);
  assert.equal(contract.annotations.idempotentHint, true);
});

void test("the mutation tool is annotated as destructive and non-idempotent", () => {
  const contract = TOOL_CONTRACTS.broker_mutate;
  assert.deepEqual([...contract.methods], MUTATION_METHODS);
  assert.equal(contract.annotations.readOnlyHint, false);
  assert.equal(
    contract.annotations.destructiveHint,
    true,
    "a DELETE-capable tool must never advertise itself as non-destructive",
  );
  assert.equal(contract.annotations.idempotentHint, false);
});

void test("no tool that can mutate is marked read-only, and vice versa", () => {
  for (const [name, contract] of Object.entries(TOOL_CONTRACTS)) {
    const canMutate = contract.methods.some((method) => MUTATION_METHODS.includes(method));
    const executes = name === "broker_read" || name === "broker_mutate";
    if (canMutate && executes) {
      assert.equal(contract.annotations.destructiveHint, true, `${name} accepts mutations but hides it`);
      assert.equal(contract.annotations.readOnlyHint, false, `${name} accepts mutations but claims read-only`);
    } else {
      assert.equal(contract.annotations.destructiveHint, false, `${name} cannot mutate yet claims to`);
      assert.equal(contract.annotations.readOnlyHint, true, `${name} should be read-only`);
    }
  }
});

void test("the server constructs against the shared fixture with a scoped secret provider", () => {
  const policy = parseBrokerPolicy(policyFixture);
  const secrets = new EnvSecretProvider(policy, "reader", { env: { TEST_GITHUB_TOKEN: "tok-abcdef" } });
  const server = createBrokerMcpServer({ policy, audit: new MemoryAuditSink(), secrets }, "reader");
  assert.ok(server);
});

void test("the server refuses an identity the policy does not provision", () => {
  const policy = parseBrokerPolicy(policyFixture);
  const secrets = new EnvSecretProvider(policy, "ghost", { env: {} });
  assert.throws(
    () => createBrokerMcpServer({ policy, audit: new MemoryAuditSink(), secrets }, "ghost"),
    /not provisioned/u,
  );
});
