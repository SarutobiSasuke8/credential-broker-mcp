import assert from "node:assert/strict";
import test from "node:test";

import { SecretRedactor } from "../src/redact.js";

const SECRET = "canary-secret-XyZ-0123456789";

function redactor(): SecretRedactor {
  return new SecretRedactor([SECRET]);
}

void test("the raw secret is redacted wherever it appears", () => {
  const out = redactor().redact(`before ${SECRET} after and again ${SECRET}`);
  assert.ok(!out.includes(SECRET));
  assert.equal(out.match(/\[REDACTED\]/gu)?.length, 2);
});

void test("the Basic-auth Base64 form is redacted", () => {
  const b64 = Buffer.from(SECRET, "utf8").toString("base64");
  const out = redactor().redact(`authorization echoed: Basic ${b64}.`);
  assert.ok(!out.includes(b64));
  assert.ok(out.includes("[REDACTED]"));
});

void test("the base64url form is redacted", () => {
  const b64url = Buffer.from(SECRET, "utf8").toString("base64url");
  const out = redactor().redact(`token=${b64url}`);
  assert.ok(!out.includes(b64url));
});

void test("percent-encoded and form-encoded forms are redacted", () => {
  const withSpecials = "canary secret+value/&=end";
  const r = new SecretRedactor([withSpecials]);
  const percent = encodeURIComponent(withSpecials);
  const form = new URLSearchParams([["k", withSpecials]]).toString().slice(2);
  const outPercent = r.redact(`https://x/?k=${percent}`);
  const outForm = r.redact(`body was k=${form}`);
  assert.ok(!outPercent.includes(percent));
  assert.ok(!outForm.includes(form));
  assert.ok(!outPercent.includes(withSpecials));
  assert.ok(!outForm.includes(withSpecials));
});

void test("NFC and NFD representations are both redacted", () => {
  const nfc = "clé-secrète-1234".normalize("NFC");
  const r = new SecretRedactor([nfc]);
  const nfd = nfc.normalize("NFD");
  assert.notEqual(nfc, nfd, "fixture must actually differ between forms");
  assert.ok(!r.redact(`x ${nfd} y`).includes(nfd));
  assert.ok(!r.redact(`x ${nfc} y`).includes(nfc));
});

void test("a truncation boundary cannot leak a secret prefix", () => {
  const body = `data data data ${SECRET}`;
  // Simulate the byte cap cutting the secret in half.
  const cut = body.slice(0, body.length - 10);
  const out = redactor().redactTruncated(cut);
  assert.ok(!out.includes(SECRET.slice(0, 12)), "no long secret prefix may survive truncation");
  assert.ok(out.includes("[REDACTED]"));
});

void test("a truncated Base64 form cannot leak either", () => {
  const b64 = Buffer.from(SECRET, "utf8").toString("base64");
  const cut = `payload: ${b64}`.slice(0, 9 + b64.length - 7);
  const out = redactor().redactTruncated(cut);
  assert.ok(!out.includes(b64.slice(0, 12)));
});

void test("error chains are redacted through nested causes", () => {
  const inner = new Error(`connect failed for https://h/?appid=${encodeURIComponent(SECRET)}`);
  const outer = new Error(`fetch failed: ${SECRET}`, { cause: inner });
  const out = redactor().redactError(outer);
  assert.ok(!out.includes(SECRET));
  assert.ok(!out.includes(encodeURIComponent(SECRET)));
});

void test("short and empty secrets do not create degenerate variants", () => {
  const r = new SecretRedactor(["", "ab"]);
  assert.equal(r.redact("nothing changes here ab-wise? actually 'ab' is too short"), "nothing changes here ab-wise? actually 'ab' is too short");
});
