/**
 * Canonical request model. Every URL an agent submits is parsed exactly once
 * into an immutable canonical value, and both policy evaluation and upstream
 * execution consume only that value. Any representation whose upstream
 * semantics cannot be proven is rejected outright: fail closed, never guess.
 *
 * Explicit semantics:
 * - Scheme: http or https only. Origin is compared exactly (scheme, host,
 *   port) after WHATWG normalisation, which lowercases hosts and drops
 *   default ports.
 * - Path: percent-decoded once, segment by segment. Decoded segments must be
 *   printable ASCII from the RFC 3986 pchar set. Encoded separators (%2F,
 *   %5C), double encoding (a decoded '%'), control characters, non-ASCII,
 *   dot segments, empty segments (repeated slashes), and segments with a
 *   trailing dot are all rejected.
 * - Trailing slashes are rejected except for the bare root path.
 * - Case: preserved and matched case-sensitively for allows; deny rules are
 *   additionally evaluated case-insensitively because many upstreams treat
 *   paths case-insensitively.
 * - Query: decoded into ordered pairs. Keys must match a strict allowpattern;
 *   values are NFC-normalised and must be free of control characters. The
 *   outbound query is re-serialised canonically from the pairs.
 * - Userinfo, fragments, backslashes, and raw control characters anywhere in
 *   the input are rejected.
 */

/** Decoded path segment: RFC 3986 pchar set, minus percent-encoding. */
const SEGMENT_CHARS = /^[A-Za-z0-9\-._~!$&'()*+,;=:@]+$/u;

/** Query parameter names the broker will ever consider. */
export const QUERY_KEY_PATTERN = /^[A-Za-z0-9_.-]{1,64}$/u;

/** Raw-input characters that make a URL unprovable: C0 controls, DEL. */
// eslint-disable-next-line no-control-regex
const RAW_CONTROL = /[\u0000-\u001F\u007F]/u;

const MAX_QUERY_VALUE_LENGTH = 512;

export interface CanonicalRequest {
  /** Lowercased scheme://host[:port], default ports elided. */
  readonly origin: string;
  /** Decoded, validated path segments. Empty for the root path. */
  readonly pathSegments: readonly string[];
  /** "/" + segments joined with "/". */
  readonly canonicalPath: string;
  /** Decoded query pairs in submission order. */
  readonly query: readonly (readonly [string, string])[];
  /** The exact outbound URL string, before credential injection. */
  readonly href: string;
}

export type CanonicalResult =
  | { ok: true; request: CanonicalRequest }
  | { ok: false; reason: string };

function fail(reason: string): CanonicalResult {
  return { ok: false, reason: `URL rejected: ${reason}` };
}

function decodeSegment(rawSegment: string): { ok: true; value: string } | { ok: false; reason: string } {
  let decoded: string;
  try {
    decoded = decodeURIComponent(rawSegment);
  } catch {
    return { ok: false, reason: "invalid percent-encoding in a path segment" };
  }
  if (decoded.includes("%")) {
    return { ok: false, reason: "double-encoded path segment (decoded form still contains '%')" };
  }
  if (decoded.includes("/") || decoded.includes("\\")) {
    return { ok: false, reason: "encoded path separator inside a segment" };
  }
  if (/[^\u0020-\u007E]/u.test(decoded)) {
    return { ok: false, reason: "non-ASCII or control character in a path segment" };
  }
  if (decoded === "." || decoded === "..") {
    return { ok: false, reason: "dot segment survived normalisation" };
  }
  if (decoded.endsWith(".")) {
    return { ok: false, reason: "path segment with a trailing dot (ambiguous on some upstreams)" };
  }
  if (!SEGMENT_CHARS.test(decoded)) {
    return { ok: false, reason: "path segment contains characters outside the safe set" };
  }
  return { ok: true, value: decoded };
}

export function serializeQuery(pairs: readonly (readonly [string, string])[]): string {
  if (pairs.length === 0) return "";
  return `?${new URLSearchParams(pairs.map(([k, v]) => [k, v])).toString()}`;
}

/**
 * Parse a raw URL string into its canonical form, or reject it with a
 * reason. This is the only place raw request URLs are ever interpreted.
 */
export function canonicalizeRequestUrl(rawUrl: string): CanonicalResult {
  if (typeof rawUrl !== "string" || rawUrl.length === 0) return fail("empty");
  if (rawUrl.length > 4_000) return fail("longer than 4000 characters");
  if (RAW_CONTROL.test(rawUrl)) return fail("raw control character in URL");
  if (rawUrl.includes("\\")) return fail("backslash in URL");
  if (rawUrl.includes(" ")) return fail("unencoded space in URL");

  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    return fail("not a valid absolute URL");
  }

  if (url.protocol !== "https:" && url.protocol !== "http:") return fail("scheme must be http or https");
  if (url.username !== "" || url.password !== "") return fail("userinfo is not permitted");
  if (url.hash !== "") return fail("fragments have no upstream meaning and are not permitted");
  if (url.origin === "null") return fail("URL has no usable origin");

  const pathname = url.pathname;
  if (!pathname.startsWith("/")) return fail("path must be absolute");

  let pathSegments: string[] = [];
  if (pathname !== "/") {
    if (pathname.endsWith("/")) return fail("trailing slash (only the bare root path may end with '/')");
    const rawSegments = pathname.slice(1).split("/");
    pathSegments = [];
    for (const rawSegment of rawSegments) {
      if (rawSegment === "") return fail("empty path segment (repeated slashes)");
      const decoded = decodeSegment(rawSegment);
      if (!decoded.ok) return fail(decoded.reason);
      pathSegments.push(decoded.value);
    }
  }

  const query: [string, string][] = [];
  for (const [key, value] of url.searchParams) {
    if (!QUERY_KEY_PATTERN.test(key)) return fail(`query parameter name '${key.slice(0, 80)}' is outside the safe set`);
    if (RAW_CONTROL.test(value)) return fail(`query parameter '${key}' carries a control character`);
    if (value.length > MAX_QUERY_VALUE_LENGTH) return fail(`query parameter '${key}' value is too long`);
    query.push([key, value.normalize("NFC")]);
  }

  const canonicalPath = `/${pathSegments.join("/")}`;
  const href = `${url.origin}${canonicalPath}${serializeQuery(query)}`;

  return {
    ok: true,
    request: Object.freeze({
      origin: url.origin,
      pathSegments: Object.freeze(pathSegments),
      canonicalPath,
      query: Object.freeze(query.map((pair) => Object.freeze(pair) as readonly [string, string])),
      href,
    }),
  };
}

/**
 * A path template is a list of segments, each a literal, "*" (exactly one
 * segment), or "**" (zero or more trailing segments, final position only).
 */
export function parsePathTemplate(template: string): string[] {
  if (!template.startsWith("/")) throw new Error(`Path template '${template}' must start with '/'.`);
  if (template === "/") return [];
  if (template.endsWith("/")) throw new Error(`Path template '${template}' must not end with '/'.`);
  const segments = template.slice(1).split("/");
  segments.forEach((segment, index) => {
    if (segment === "**") {
      if (index !== segments.length - 1) throw new Error(`'**' may only appear as the final segment of '${template}'.`);
      return;
    }
    if (segment === "*") return;
    const decoded = decodeSegment(segment);
    if (!decoded.ok || decoded.value !== segment) {
      throw new Error(`Path template '${template}' has an invalid segment '${segment}': segments must be literal, '*', or a trailing '**'.`);
    }
  });
  return segments;
}

/** Match canonical path segments against a template. */
export function matchPathTemplate(
  template: readonly string[],
  segments: readonly string[],
  options: { caseInsensitive?: boolean } = {},
): boolean {
  const eq = options.caseInsensitive
    ? (a: string, b: string) => a.toLowerCase() === b.toLowerCase()
    : (a: string, b: string) => a === b;
  for (let i = 0; i < template.length; i += 1) {
    const part = template[i];
    if (part === "**") return true; // matches zero or more remaining segments
    if (i >= segments.length) return false;
    const segment = segments[i];
    if (segment === undefined || part === undefined) return false;
    if (part === "*") continue;
    if (!eq(part, segment)) return false;
  }
  return template.length === segments.length;
}
