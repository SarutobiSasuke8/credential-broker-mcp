import assert from "node:assert/strict";
import test from "node:test";

import { canonicalizeRequestUrl, matchPathTemplate, parsePathTemplate } from "../src/canonical.js";

function expectRejected(rawUrl: string, why: string): void {
  const result = canonicalizeRequestUrl(rawUrl);
  assert.equal(result.ok, false, `${why}: '${rawUrl}' must be rejected`);
}

function expectPath(rawUrl: string, canonicalPath: string): void {
  const result = canonicalizeRequestUrl(rawUrl);
  assert.ok(result.ok, `expected '${rawUrl}' to canonicalise, got rejection`);
  assert.equal(result.request.canonicalPath, canonicalPath);
}

void test("plain paths canonicalise to themselves", () => {
  expectPath("https://api.example.com/repos/a/b", "/repos/a/b");
  expectPath("https://api.example.com/", "/");
  expectPath("https://api.example.com", "/");
});

void test("percent-encoded letters decode so every representation is one canonical form", () => {
  // /%61dmin is the same upstream endpoint as /admin; policy must see /admin.
  expectPath("https://api.example.com/%61dmin/panel", "/admin/panel");
  expectPath("https://api.example.com/%41dmin", "/Admin");
});

void test("encoded separators are rejected outright", () => {
  expectRejected("https://api.example.com/admin%2Fpanel", "encoded slash");
  expectRejected("https://api.example.com/admin%2fpanel", "encoded slash lowercase");
  expectRejected("https://api.example.com/admin%5Cpanel", "encoded backslash");
  expectRejected("https://api.example.com/admin%5cpanel", "encoded backslash lowercase");
});

void test("double encoding is rejected", () => {
  // %252F decodes once to %2F: the decoded form still contains '%'.
  expectRejected("https://api.example.com/admin%252Fpanel", "double-encoded slash");
  expectRejected("https://api.example.com/%2561dmin", "double-encoded letter");
});

void test("invalid percent-encoding is rejected", () => {
  expectRejected("https://api.example.com/a%ZZb", "invalid hex");
  expectRejected("https://api.example.com/a%2", "truncated escape");
});

void test("raw and encoded control characters are rejected", () => {
  expectRejected("https://api.example.com/a%00b", "encoded NUL");
  expectRejected("https://api.example.com/a%0Ab", "encoded newline");
  expectRejected("https://api.example.com/a\tb", "raw tab");
});

void test("backslashes anywhere are rejected before the URL parser can fold them", () => {
  // WHATWG URL treats backslash as a path separator in special schemes.
  expectRejected("https://api.example.com\\admin", "raw backslash after host");
  expectRejected("https://api.example.com/a\\b", "raw backslash in path");
});

void test("userinfo and fragments are rejected", () => {
  expectRejected("https://user:pass@api.example.com/a", "userinfo");
  expectRejected("https://user@api.example.com/a", "username only");
  expectRejected("https://api.example.com/a#frag", "fragment");
});

void test("dot segments cannot survive in any encoding", () => {
  // The WHATWG parser resolves dot segments, literal or percent-encoded,
  // before the broker ever sees the path, so every representation collapses
  // to one canonical form and none can escape upward past policy.
  expectPath("https://api.example.com/a/../b", "/b");
  expectPath("https://api.example.com/a/./b", "/a/b");
  expectPath("https://api.example.com/a/%2e%2e/b", "/b");
  expectPath("https://api.example.com/a/%2E%2E/b", "/b");
  expectPath("https://api.example.com/a/%2e/b", "/a/b");
  // Double-encoded dot segments are rejected rather than interpreted.
  expectRejected("https://api.example.com/a/%252e%252e/b", "double-encoded dot-dot");
});

void test("repeated slashes, trailing slashes, and trailing dots are rejected", () => {
  expectRejected("https://api.example.com//admin", "repeated slash");
  expectRejected("https://api.example.com/a//b", "interior repeated slash");
  expectRejected("https://api.example.com/admin/", "trailing slash");
  expectRejected("https://api.example.com/admin./x", "trailing dot in segment");
  expectRejected("https://api.example.com/admin.", "trailing dot final segment");
});

void test("non-ASCII path segments are rejected in both NFC and NFD forms", () => {
  expectRejected("https://api.example.com/café", "NFC e-acute");
  expectRejected("https://api.example.com/café", "NFD combining accent");
  expectRejected("https://api.example.com/%C3%A9", "encoded non-ASCII");
  // Fullwidth 'a' (U+FF41) must not be treated as 'a'.
  expectRejected("https://api.example.com/ａdmin", "fullwidth lookalike");
});

void test("spaces are rejected raw and decoded", () => {
  expectRejected("https://api.example.com/a b", "raw space");
  expectRejected("https://api.example.com/a%20b", "encoded space");
});

void test("only http and https schemes with a usable origin are accepted", () => {
  expectRejected("ftp://api.example.com/a", "ftp scheme");
  expectRejected("file:///etc/passwd", "file scheme");
  expectRejected("not a url", "garbage");
  expectRejected("", "empty");
});

void test("query parameters are decoded, validated, and canonically re-serialised", () => {
  const result = canonicalizeRequestUrl("https://api.example.com/weather?q=London&units=metric");
  assert.ok(result.ok);
  assert.deepEqual(
    result.request.query.map((pair) => [...pair]),
    [
      ["q", "London"],
      ["units", "metric"],
    ],
  );
  assert.equal(result.request.href, "https://api.example.com/weather?q=London&units=metric");
});

void test("query keys outside the safe set and control values are rejected", () => {
  expectRejected("https://api.example.com/a?bad%00key=1", "control in key");
  expectRejected("https://api.example.com/a?k=%00", "control in value");
  expectRejected("https://api.example.com/a?k[]=1", "brackets in key");
});

void test("the canonical href is stable under re-canonicalisation", () => {
  const first = canonicalizeRequestUrl("https://API.Example.com:443/%61/b?x=1%202");
  assert.ok(first.ok);
  const second = canonicalizeRequestUrl(first.request.href);
  assert.ok(second.ok);
  assert.equal(second.request.href, first.request.href);
  assert.equal(second.request.canonicalPath, first.request.canonicalPath);
  assert.equal(second.request.origin, "https://api.example.com");
});

void test("path templates parse and match segment-wise", () => {
  assert.deepEqual(parsePathTemplate("/repos/*/*"), ["repos", "*", "*"]);
  assert.deepEqual(parsePathTemplate("/"), []);
  assert.throws(() => parsePathTemplate("/a/**/b"), /final segment/u);
  assert.throws(() => parsePathTemplate("no-slash"), /must start/u);
  assert.throws(() => parsePathTemplate("/a/"), /must not end/u);
  assert.throws(() => parsePathTemplate("/a/%2F"), /invalid segment/u);

  assert.ok(matchPathTemplate(["repos", "*", "*"], ["repos", "a", "b"]));
  assert.ok(!matchPathTemplate(["repos", "*", "*"], ["repos", "a"]));
  assert.ok(!matchPathTemplate(["repos", "*", "*"], ["repos", "a", "b", "c"]));
  assert.ok(matchPathTemplate(["repos", "**"], ["repos"]));
  assert.ok(matchPathTemplate(["repos", "**"], ["repos", "a", "b"]));
  assert.ok(!matchPathTemplate(["repos", "**"], ["other"]));
  assert.ok(!matchPathTemplate(["admin"], ["Admin"]));
  assert.ok(matchPathTemplate(["admin"], ["Admin"], { caseInsensitive: true }));
});
