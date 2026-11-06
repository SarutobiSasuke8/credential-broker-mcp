import assert from "node:assert/strict";
import test from "node:test";

import { applyMetaUpdate, attentionList, EMPTY_META, expiryStatus, parseKeyMeta, serializeKeyMeta } from "../src/key-meta.js";

const NOW = new Date("2026-11-06T15:30:00Z");

void test("expiry status counts whole days and treats the expiry date as the last valid day", () => {
  assert.deepEqual(expiryStatus(null, NOW), { state: "none", days: null });
  assert.deepEqual(expiryStatus("2026-11-06", NOW), { state: "soon", days: 0 });
  assert.deepEqual(expiryStatus("2026-11-05", NOW), { state: "expired", days: -1 });
  assert.deepEqual(expiryStatus("2026-12-06", NOW), { state: "soon", days: 30 });
  assert.deepEqual(expiryStatus("2026-12-07", NOW), { state: "ok", days: 31 });
  assert.deepEqual(expiryStatus("not-a-date", NOW), { state: "none", days: null });
});

void test("updates validate dates, trim notes, and remove empty entries", () => {
  const added = applyMetaUpdate(EMPTY_META, "itch", { expires: "2027-01-31", note: "  created for butler  " }, NOW);
  assert.equal(added.keys["itch"]?.expires, "2027-01-31");
  assert.equal(added.keys["itch"]?.note, "created for butler");
  assert.equal(added.keys["itch"]?.updatedAt, NOW.toISOString());

  assert.throws(() => applyMetaUpdate(EMPTY_META, "itch", { expires: "2027-02-30", note: "" }), /real expiry date/u);
  assert.throws(() => applyMetaUpdate(EMPTY_META, "itch", { expires: "31/01/2027", note: "" }), /real expiry date/u);
  assert.throws(() => applyMetaUpdate(EMPTY_META, "itch", { expires: null, note: "x".repeat(501) }), /under 500/u);

  const cleared = applyMetaUpdate(added, "itch", { expires: null, note: "" }, NOW);
  assert.deepEqual(cleared.keys, {});
});

void test("unreadable or invalid files fall back to an empty set instead of blocking the page", () => {
  assert.deepEqual(parseKeyMeta(null).keys, {});
  assert.deepEqual(parseKeyMeta("{ nope").keys, {});
  assert.deepEqual(parseKeyMeta(JSON.stringify({ version: 2, keys: {} })).keys, {});
  assert.deepEqual(parseKeyMeta(JSON.stringify({ version: 1, keys: { a: { expires: "2026-13-40" } } })).keys, {});
});

void test("serialisation round-trips with stable key order", () => {
  let file = applyMetaUpdate(EMPTY_META, "zeta", { expires: "2027-01-01", note: "" }, NOW);
  file = applyMetaUpdate(file, "alpha", { expires: null, note: "no expiry" }, NOW);
  const text = serializeKeyMeta(file);
  assert.ok(text.indexOf('"alpha"') < text.indexOf('"zeta"'));
  assert.deepEqual(parseKeyMeta(text), file);
});

void test("attention list holds expired and soon keys, soonest first", () => {
  let file = EMPTY_META;
  file = applyMetaUpdate(file, "later", { expires: "2027-06-01", note: "" }, NOW);
  file = applyMetaUpdate(file, "soon", { expires: "2026-11-20", note: "" }, NOW);
  file = applyMetaUpdate(file, "gone", { expires: "2026-10-01", note: "" }, NOW);
  assert.deepEqual(attentionList(file, NOW).map((row) => row.id), ["gone", "soon"]);
});
