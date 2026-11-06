/**
 * Pure logic for the key manager page: routing, search ranking, CSV export
 * and small formatters. No DOM here, so it is unit tested in Node and shared
 * with the page unchanged.
 */

// ---- routes ----------------------------------------------------------------

export const PAGES = ["overview", "keys", "agents", "approvals", "activity", "import", "settings"] as const;
export type Page = (typeof PAGES)[number];

export interface Route {
  page: Page;
  /** An item to select on that page, e.g. a key id. */
  item: string | null;
}

/** "#/keys/github" to { page: "keys", item: "github" }. Anything unknown is the overview. */
export function parseRoute(hash: string): Route {
  const clean = hash.replace(/^#\/?/u, "");
  const [rawPage = "", ...rest] = clean.split("/");
  const known = (PAGES as readonly string[]).includes(rawPage);
  const page = known ? (rawPage as Page) : "overview";
  const item = known && rest.length > 0 ? decodeURIComponent(rest.join("/")) : null;
  return { page, item: item && item.length > 0 ? item : null };
}

export function routeHash(page: Page, item: string | null = null): string {
  return item ? `#/${page}/${encodeURIComponent(item)}` : `#/${page}`;
}

// ---- search ----------------------------------------------------------------

export type SearchKind = "key" | "agent" | "approval" | "provider";

export interface SearchItem {
  kind: SearchKind;
  /** What is matched first and shown in bold. */
  title: string;
  /** Secondary text, matched second. */
  subtitle: string;
  /** Where Enter takes you. */
  page: Page;
  item: string | null;
  /** Extra searchable words that are not shown. */
  keywords?: string;
}

export interface SearchHit {
  item: SearchItem;
  /** 3 exact title, 2 title prefix, 1 title contains, 0 matched elsewhere. */
  tier: number;
  score: number;
}

const KIND_ORDER: Record<SearchKind, number> = { key: 0, agent: 1, approval: 2, provider: 3 };

function tierOf(field: string, query: string): number {
  const text = field.toLowerCase();
  if (text === query) return 3;
  if (text.startsWith(query)) return 2;
  if (text.includes(query)) return 1;
  return 0;
}

/**
 * Ranks items for a query. How well the title matches decides first (exact,
 * prefix, contains), then the kind (keys before agents, approvals and
 * providers), then how much of the rest matched.
 */
export function rankSearch(items: readonly SearchItem[], rawQuery: string, limit = 12): SearchHit[] {
  const query = rawQuery.trim().toLowerCase();
  if (!query) return [];
  const words = query.split(/\s+/u).filter(Boolean);
  const hits: SearchHit[] = [];
  for (const item of items) {
    const tier = tierOf(item.title, query);
    let score = tier * 10 + tierOf(item.subtitle, query) * 3 + (item.keywords ? tierOf(item.keywords, query) : 0);
    if (score === 0 && words.length > 1) {
      const haystack = `${item.title} ${item.subtitle} ${item.keywords ?? ""}`.toLowerCase();
      if (words.every((w) => haystack.includes(w))) score = 1;
    }
    if (score > 0) hits.push({ item, tier, score });
  }
  hits.sort((a, b) => b.tier - a.tier || KIND_ORDER[a.item.kind] - KIND_ORDER[b.item.kind] || b.score - a.score || a.item.title.localeCompare(b.item.title));
  return hits.slice(0, limit);
}

/** Groups ranked hits by kind, keeping the rank order inside each group and the group order by best hit. */
export function groupHits(hits: readonly SearchHit[]): { kind: SearchKind; hits: SearchHit[] }[] {
  const groups = new Map<SearchKind, SearchHit[]>();
  for (const hit of hits) {
    const list = groups.get(hit.item.kind) ?? [];
    list.push(hit);
    groups.set(hit.item.kind, list);
  }
  return [...groups].map(([kind, list]) => ({ kind, hits: list }));
}

// ---- CSV -------------------------------------------------------------------

/** RFC 4180 style: quote when needed, double the quotes, CRLF line ends. Leading formula characters are neutralised. */
export function toCsv(header: readonly string[], rows: readonly (readonly (string | number | null | undefined)[])[]): string {
  const cell = (value: string | number | null | undefined): string => {
    let text = value === null || value === undefined ? "" : String(value);
    if (/^[=+\-@\t\r]/u.test(text)) text = `'${text}`;
    return /[",\r\n]/u.test(text) ? `"${text.replace(/"/gu, '""')}"` : text;
  };
  return [header, ...rows].map((row) => row.map(cell).join(",")).join("\r\n") + "\r\n";
}

// ---- activity filters --------------------------------------------------------

export interface ActivityRecord {
  at: string;
  agentId: string;
  credentialId: string;
  method: string;
  host: string;
  pathname: string;
  outcome: string;
  status: number | null;
}

export interface ActivityFilter {
  agent: string;
  credential: string;
  outcome: string;
  /** Hours back from now; 0 means everything. */
  hours: number;
}

export const EMPTY_FILTER: ActivityFilter = { agent: "", credential: "", outcome: "", hours: 0 };

export function filterActivity(records: readonly ActivityRecord[], filter: ActivityFilter, now: Date = new Date()): ActivityRecord[] {
  const cutoff = filter.hours > 0 ? now.getTime() - filter.hours * 3_600_000 : Number.NEGATIVE_INFINITY;
  return records.filter((r) => {
    if (filter.agent && r.agentId !== filter.agent) return false;
    if (filter.credential && r.credentialId !== filter.credential) return false;
    if (filter.outcome && r.outcome !== filter.outcome) return false;
    if (filter.hours > 0) {
      const when = Date.parse(r.at);
      if (Number.isNaN(when) || when < cutoff) return false;
    }
    return true;
  });
}

// ---- formatting ------------------------------------------------------------

export function ago(iso: string, now: Date = new Date()): string {
  const ms = now.getTime() - Date.parse(iso);
  if (Number.isNaN(ms)) return "";
  const mins = Math.round(ms / 60_000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins} min ago`;
  const hours = Math.round(mins / 60);
  if (hours < 48) return hours === 1 ? "1 hour ago" : `${hours} hours ago`;
  const days = Math.round(hours / 24);
  return `${days} days ago`;
}

export type ExpiryState = "none" | "ok" | "soon" | "expired";

export interface ExpiryLike {
  expiryState: ExpiryState;
  expiryDays: number | null;
  expires: string | null;
}

export function expiryText(c: ExpiryLike): { kind: "none" | "ok" | "soon" | "expired"; text: string } {
  const d = c.expiryDays;
  if (c.expiryState === "none") return { kind: "none", text: "No expiry" };
  if (c.expiryState === "expired") return { kind: "expired", text: d === -1 ? "Expired yesterday" : `Expired ${-(d ?? 0)} days ago` };
  if (d === 0) return { kind: "soon", text: "Expires today" };
  if (c.expiryState === "soon") return { kind: "soon", text: d === 1 ? "Expires tomorrow" : `Expires in ${d} days` };
  return { kind: "ok", text: `Expires ${c.expires ?? ""}` };
}

/** Sort rank for the keys table default order: most urgent first. */
export function urgency(c: ExpiryLike & { source: string; paused?: boolean }): number {
  if (c.paused) return 0;
  if (c.expiryState === "expired") return 1;
  if (c.expiryState === "soon") return 2;
  if (c.source === "missing") return 3;
  return 4;
}

export function isoPlusDays(days: number, from: Date = new Date()): string {
  const d = new Date(from);
  d.setDate(d.getDate() + days);
  const m = String(d.getMonth() + 1).padStart(2, "0");
  const day = String(d.getDate()).padStart(2, "0");
  return `${d.getFullYear()}-${m}-${day}`;
}

/** Decodes the "<token>[.<prefill>]" fragment the key manager prints. */
export function parseLaunchFragment(hash: string): { token: string; prefill: unknown | null } {
  const parts = hash.replace(/^#/u, "").split(".");
  const token = parts[0] ?? "";
  let prefill: unknown = null;
  if (parts[1]) {
    try {
      const bin = atob(parts[1].replace(/-/gu, "+").replace(/_/gu, "/"));
      const bytes = Uint8Array.from(bin, (ch) => ch.charCodeAt(0));
      prefill = JSON.parse(new TextDecoder().decode(bytes));
    } catch {
      prefill = null;
    }
  }
  return { token: /^[0-9a-f]{64}$/u.test(token) ? token : "", prefill };
}

/** Sort rows by a column with a stable tiebreak on the id. */
export function sortRows<T extends { id: string }>(rows: readonly T[], key: (row: T) => string | number | null, direction: "asc" | "desc"): T[] {
  const sign = direction === "asc" ? 1 : -1;
  return [...rows].sort((a, b) => {
    const ka = key(a);
    const kb = key(b);
    if (ka === kb) return a.id.localeCompare(b.id);
    if (ka === null) return 1;
    if (kb === null) return -1;
    if (typeof ka === "number" && typeof kb === "number") return (ka - kb) * sign;
    return String(ka).localeCompare(String(kb)) * sign;
  });
}
