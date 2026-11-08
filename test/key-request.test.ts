import assert from "node:assert/strict";
import test from "node:test";

import { findPresetById } from "../src/import-scan.js";
import { handleKeyRequest, KeyRequester, keyRequestInputSchema } from "../src/key-request.js";

import type { KeyRequest } from "../src/key-request.js";

function harness(options: { provisioned?: boolean; launchFails?: boolean } = {}) {
  const launched: KeyRequest[] = [];
  const audit: { credentialId: string; detail: string }[] = [];
  let clock = 1_000_000;
  const requester = new KeyRequester({
    now: () => clock,
    launcher: {
      launch(request) {
        if (options.launchFails) throw new Error("spawn failed");
        launched.push(request);
      },
    },
  });
  const deps = {
    requester,
    agentId: "claude",
    isProvisioned: () => options.provisioned ?? false,
    recordAudit: (credentialId: string, detail: string) => {
      audit.push({ credentialId, detail });
      return Promise.resolve();
    },
  };
  return { deps, launched, audit, advance: (ms: number) => { clock += ms; } };
}

void test("a request opens the key manager once and records a content-free audit line", async () => {
  const { deps, launched, audit } = harness();
  const result = await handleKeyRequest(deps, { credential: "itch", reason: "Upload the Void Cascade build", provider: "itch" });
  assert.equal(result.isError, false);
  assert.equal(result.payload["status"], "opened");
  assert.deepEqual(launched, [{ credentialId: "itch", reason: "Upload the Void Cascade build", requestedBy: "claude", provider: "itch" }]);
  assert.deepEqual(audit, [{ credentialId: "itch", detail: "key request opened" }]);
  const text = JSON.stringify(result.payload);
  assert.doesNotMatch(text, /http|token|127\.0\.0\.1/u, "the agent must never be shown a page address or token");
});

void test("the same credential cannot be requested again within ten minutes", async () => {
  const { deps, launched, advance } = harness();
  await handleKeyRequest(deps, { credential: "itch", reason: "first request" });
  const second = await handleKeyRequest(deps, { credential: "itch", reason: "second request" });
  assert.equal(second.isError, true);
  assert.equal(second.payload["status"], "rate_limited");
  assert.equal(launched.length, 1);
  advance(10 * 60_000 + 1);
  const third = await handleKeyRequest(deps, { credential: "itch", reason: "third request" });
  assert.equal(third.payload["status"], "opened");
  assert.equal(launched.length, 2);
});

void test("the process cannot open more than five windows an hour across credentials", async () => {
  const { deps, launched } = harness();
  for (const id of ["aa", "bb", "cc", "dd", "ee"]) {
    assert.equal((await handleKeyRequest(deps, { credential: id, reason: "needed for a task" })).payload["status"], "opened");
  }
  const sixth = await handleKeyRequest(deps, { credential: "ff", reason: "needed for a task" });
  assert.equal(sixth.payload["status"], "rate_limited");
  assert.equal(launched.length, 5);
});

void test("an already provisioned credential opens nothing", async () => {
  const { deps, launched, audit } = harness({ provisioned: true });
  const result = await handleKeyRequest(deps, { credential: "github", reason: "read repos" });
  assert.equal(result.payload["status"], "already_provisioned");
  assert.equal(launched.length, 0);
  assert.match(audit[0]?.detail ?? "", /already provisioned/u);
});

void test("a launcher failure is reported without claiming a window opened", async () => {
  const { deps, launched, advance } = harness({ launchFails: true });
  const result = await handleKeyRequest(deps, { credential: "itch", reason: "upload a build" });
  assert.equal(result.isError, true);
  assert.equal(result.payload["status"], "unavailable");
  assert.equal(launched.length, 0);
  advance(1);
  assert.equal((await handleKeyRequest(deps, { credential: "itch", reason: "retry the upload" })).payload["status"], "unavailable");
});

void test("input is validated: lowercase ids only, a real reason, no free-form address", () => {
  assert.throws(() => keyRequestInputSchema.parse({ credential: "Itch Key", reason: "upload" }));
  assert.throws(() => keyRequestInputSchema.parse({ credential: "itch", reason: "" }));
  assert.throws(() => keyRequestInputSchema.parse({ credential: "itch", reason: "x".repeat(201) }));
  const parsed = keyRequestInputSchema.parse({ credential: "itch", reason: "upload", baseUrl: "https://evil.example" });
  assert.equal("baseUrl" in parsed, false, "an agent-supplied address is dropped, never used");
});

void test("provider presets come from the broker's own table", () => {
  assert.equal(findPresetById("itch")?.baseUrl, "https://api.itch.io");
  assert.equal(findPresetById("github")?.baseUrl, "https://api.github.com");
  assert.equal(findPresetById("not-a-provider"), null);
});
