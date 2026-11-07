import assert from "node:assert/strict";
import test from "node:test";

import { accessChip, ago, expiryText, filterActivity, groupHits, isoPlusDays, keysEmptyState, parseLaunchFragment, parseRoute, rankSearch, routeHash, sortRows, toCsv, unconnectedDetail, urgency } from "../src/ui/logic.js";

import type { ActivityRecord, SearchItem } from "../src/ui/logic.js";

const NOW = new Date("2026-11-06T12:00:00Z");

void test("routes parse and serialise, and anything unknown lands on the overview", () => {
  assert.deepEqual(parseRoute("#/keys/github"), { page: "keys", item: "github" });
  assert.deepEqual(parseRoute("#/keys"), { page: "keys", item: null });
  assert.deepEqual(parseRoute("#keys"), { page: "keys", item: null });
  assert.deepEqual(parseRoute(""), { page: "overview", item: null });
  assert.deepEqual(parseRoute("#/nope/x"), { page: "overview", item: null });
  assert.deepEqual(parseRoute("#/agents/a%20b"), { page: "agents", item: "a b" });
  assert.equal(routeHash("keys", "a b"), "#/keys/a%20b");
  assert.equal(routeHash("activity"), "#/activity");
  assert.deepEqual(parseRoute(routeHash("keys", "x/y")), { page: "keys", item: "x/y" });
});

const ITEMS: SearchItem[] = [
  { kind: "key", title: "github", subtitle: "GitHub read token · https://api.github.com", page: "keys", item: "github" },
  { kind: "key", title: "gitlab", subtitle: "GitLab", page: "keys", item: "gitlab" },
  { kind: "agent", title: "claude", subtitle: "Claude Code", page: "agents", item: "claude" },
  { kind: "provider", title: "GitHub", subtitle: "https://api.github.com", page: "keys", item: null, keywords: "github" },
  { kind: "approval", title: "appr-1", subtitle: "claude · github · create-issue", page: "approvals", item: "appr-1" },
];

void test("search ranks exact ids first, then prefixes, then mentions, and groups by kind", () => {
  const hits = rankSearch(ITEMS, "github");
  assert.equal(hits[0]?.item.kind, "key");
  assert.equal(hits[0]?.item.title, "github");
  assert.equal(hits[1]?.item.kind, "provider", "an exact provider name ranks above a mention");
  assert.ok(hits.some((h) => h.item.kind === "approval"), "mentions still show");
  assert.deepEqual(rankSearch(ITEMS, "git").map((h) => h.item.title), ["github", "gitlab", "GitHub", "appr-1"]);
  assert.deepEqual(rankSearch(ITEMS, "   "), []);
  assert.deepEqual(rankSearch(ITEMS, "claude issue").map((h) => h.item.title), ["appr-1"], "several words must all match");
  assert.equal(rankSearch(ITEMS, "g", 2).length, 2, "the limit applies");
  const groups = groupHits(rankSearch(ITEMS, "git"));
  assert.deepEqual(groups.map((g) => g.kind), ["key", "provider", "approval"]);
  assert.equal(groups[0]?.hits.length, 2);
});

void test("CSV quotes what needs quoting, doubles quotes, neutralises formulas, and ends lines with CRLF", () => {
  const csv = toCsv(["a", "b"], [["plain", 'say "hi"'], ["x,y", "=SUM(1)"], [null, 3]]);
  assert.equal(csv, 'a,b\r\nplain,"say ""hi"""\r\n"x,y",\'=SUM(1)\r\n,3\r\n');
});

void test("activity filters combine agent, key, outcome and a time window", () => {
  const rec = (over: Partial<ActivityRecord>): ActivityRecord => ({
    at: "2026-11-06T11:30:00Z", agentId: "claude", credentialId: "github", method: "GET", host: "api.github.com", pathname: "/x", outcome: "succeeded", status: 200, ...over,
  });
  const records = [rec({}), rec({ agentId: "codex", outcome: "denied", status: null }), rec({ at: "2026-11-01T00:00:00Z" }), rec({ at: "bad date" })];
  assert.equal(filterActivity(records, { agent: "", credential: "", outcome: "", hours: 0 }, NOW).length, 4);
  assert.equal(filterActivity(records, { agent: "codex", credential: "", outcome: "", hours: 0 }, NOW).length, 1);
  assert.equal(filterActivity(records, { agent: "", credential: "github", outcome: "succeeded", hours: 0 }, NOW).length, 3);
  assert.equal(filterActivity(records, { agent: "", credential: "", outcome: "", hours: 24 }, NOW).length, 2, "old and unparseable dates fall outside a window");
});

void test("formatters are plain and stable", () => {
  assert.equal(ago("2026-11-06T11:59:40Z", NOW), "just now");
  assert.equal(ago("2026-11-06T11:15:00Z", NOW), "45 min ago");
  assert.equal(ago("2026-11-06T11:00:00Z", NOW), "1 hour ago");
  assert.equal(ago("2026-11-03T12:00:00Z", NOW), "3 days ago");
  assert.equal(ago("nope", NOW), "");
  assert.deepEqual(expiryText({ expiryState: "expired", expiryDays: -1, expires: "2026-11-05" }), { kind: "expired", text: "Expired yesterday" });
  assert.deepEqual(expiryText({ expiryState: "soon", expiryDays: 0, expires: "2026-11-06" }), { kind: "soon", text: "Expires today" });
  assert.deepEqual(expiryText({ expiryState: "ok", expiryDays: 90, expires: "2027-02-04" }), { kind: "ok", text: "Expires 2027-02-04" });
  assert.equal(isoPlusDays(30, NOW), "2026-12-06");
  assert.deepEqual(
    [
      { source: "keychain", expiryState: "ok", expiryDays: 9, expires: null },
      { source: "missing", expiryState: "none", expiryDays: null, expires: null },
      { source: "keychain", expiryState: "expired", expiryDays: -3, expires: null },
      { source: "keychain", expiryState: "ok", expiryDays: 9, expires: null, paused: true },
    ].map((c) => urgency(c as never)),
    [4, 3, 1, 0],
  );
});

void test("the launch fragment yields the token and a decoded prefill, and rejects a malformed token", () => {
  const token = "ab".repeat(32);
  const prefill = Buffer.from(JSON.stringify({ id: "openai", reason: "x" }), "utf8").toString("base64url");
  assert.deepEqual(parseLaunchFragment(`#${token}.${prefill}`), { token, prefill: { id: "openai", reason: "x" } });
  assert.deepEqual(parseLaunchFragment(`#${token}`), { token, prefill: null });
  assert.deepEqual(parseLaunchFragment(`#${token}.not-base64-json`), { token, prefill: null });
  assert.deepEqual(parseLaunchFragment("#/keys"), { token: "", prefill: null });
});

void test("the Keys page says No keys yet only when there is nothing anywhere, and points at unconnected keys otherwise", () => {
  assert.equal(keysEmptyState({ policyExists: false, credentials: 0, unconnected: 0, visible: 0 }), "none");
  assert.equal(keysEmptyState({ policyExists: true, credentials: 0, unconnected: 0, visible: 0 }), "no-apis");
  assert.equal(keysEmptyState({ policyExists: false, credentials: 0, unconnected: 7, visible: 0 }), "unconnected", "saved keys are never called no keys");
  assert.equal(keysEmptyState({ policyExists: true, credentials: 0, unconnected: 1, visible: 0 }), "unconnected");
  assert.equal(keysEmptyState({ policyExists: true, credentials: 3, unconnected: 2, visible: 0 }), "filtered", "a filter that hides every API is not an empty policy");
  assert.equal(keysEmptyState({ policyExists: true, credentials: 3, unconnected: 2, visible: 3 }), null);
  assert.equal(unconnectedDetail("Windows Credential Manager"), "Saved in Windows Credential Manager, but no API in the policy uses it, so no agent can use it.");
  assert.equal(unconnectedDetail(null), "Saved in the keychain, but no API in the policy uses it, so no agent can use it.");
});

void test("the header chip reports pause first, then whether any agent can reach anything", () => {
  const live = { all: null, unreadable: false, active: false };
  assert.deepEqual(accessChip(live, 0), { kind: "idle", label: "No agent access yet" });
  assert.deepEqual(accessChip(live, 2), { kind: "live", label: "All access live" });
  assert.deepEqual(accessChip({ ...live, active: true }, 2), { kind: "partial", label: "Partly paused" });
  assert.deepEqual(accessChip({ all: { at: "x", reason: "" }, unreadable: false, active: true }, 2), { kind: "paused", label: "Paused" });
  assert.deepEqual(accessChip({ all: null, unreadable: true, active: true }, 0), { kind: "paused", label: "Paused" });
});

void test("rows sort by any column in either direction with nulls last and a stable id tiebreak", () => {
  const rows = [{ id: "b", n: 2 as number | null }, { id: "a", n: 2 as number | null }, { id: "c", n: null }, { id: "d", n: 1 as number | null }];
  assert.deepEqual(sortRows(rows, (r) => r.n, "asc").map((r) => r.id), ["d", "a", "b", "c"]);
  assert.deepEqual(sortRows(rows, (r) => r.n, "desc").map((r) => r.id), ["a", "b", "d", "c"]);
  assert.deepEqual(sortRows(rows, (r) => r.id, "desc").map((r) => r.id), ["d", "c", "b", "a"]);
});
