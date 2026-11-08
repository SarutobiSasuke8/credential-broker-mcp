import { z } from "zod";

/**
 * Non-secret notes about a key: when it expires and a free-text reminder.
 * Kept in a small JSON file next to the policy, never in the policy itself
 * (the policy parser rejects unknown fields on purpose) and never with the
 * secret. Nothing here widens access or is read by the broker engine.
 */

export const MAX_NOTE_LENGTH = 500;
/** Keys expiring within this many days are flagged as "soon". */
export const EXPIRY_WARNING_DAYS = 30;

const DATE_ONLY = /^\d{4}-\d{2}-\d{2}$/u;

function isRealDate(value: string): boolean {
  if (!DATE_ONLY.test(value)) return false;
  const parsed = new Date(`${value}T00:00:00Z`);
  return !Number.isNaN(parsed.getTime()) && parsed.toISOString().startsWith(value);
}

const entrySchema = z.object({
  expires: z.string().refine(isRealDate, "Use a real date as YYYY-MM-DD.").nullable().default(null),
  note: z.string().max(MAX_NOTE_LENGTH).default(""),
  updatedAt: z.string().default(""),
  /** When the key was last replaced through the key manager. */
  rotatedAt: z.string().nullable().default(null),
});

const fileSchema = z.object({
  version: z.literal(1),
  keys: z.record(z.string(), entrySchema),
});

export type KeyMeta = z.infer<typeof entrySchema>;
export type KeyMetaFile = z.infer<typeof fileSchema>;

export const EMPTY_META: KeyMetaFile = { version: 1, keys: {} };

/** An unreadable or invalid file yields an empty set instead of blocking the page. */
export function parseKeyMeta(text: string | null): KeyMetaFile {
  if (!text) return { version: 1, keys: {} };
  try {
    return fileSchema.parse(JSON.parse(text));
  } catch {
    return { version: 1, keys: {} };
  }
}

export function serializeKeyMeta(file: KeyMetaFile): string {
  const sorted = Object.fromEntries(Object.entries(file.keys).sort(([a], [b]) => a.localeCompare(b)));
  return `${JSON.stringify({ version: 1, keys: sorted }, null, 2)}\n`;
}

export interface MetaUpdate {
  expires: string | null;
  note: string;
}

/** Validates one update and returns a new file value. Empty input removes the entry. */
export function applyMetaUpdate(file: KeyMetaFile, id: string, update: MetaUpdate, now: Date = new Date()): KeyMetaFile {
  const expires = update.expires?.trim() ? update.expires.trim() : null;
  if (expires !== null && !isRealDate(expires)) throw new Error("Use a real expiry date as YYYY-MM-DD.");
  const note = update.note.trim();
  if (note.length > MAX_NOTE_LENGTH) throw new Error(`Keep notes under ${MAX_NOTE_LENGTH} characters.`);
  const keys = { ...file.keys };
  const rotatedAt = keys[id]?.rotatedAt ?? null;
  if (expires === null && note === "" && rotatedAt === null) delete keys[id];
  else keys[id] = { expires, note, updatedAt: now.toISOString(), rotatedAt };
  return { version: 1, keys };
}

/** Records that a key was just replaced. Keeps any expiry and note already set. */
export function markRotated(file: KeyMetaFile, id: string, now: Date = new Date()): KeyMetaFile {
  const current = file.keys[id];
  return {
    version: 1,
    keys: { ...file.keys, [id]: { expires: current?.expires ?? null, note: current?.note ?? "", updatedAt: now.toISOString(), rotatedAt: now.toISOString() } },
  };
}

export type ExpiryState = "none" | "ok" | "soon" | "expired";

export interface ExpiryStatus {
  state: ExpiryState;
  /** Whole days until expiry; negative once expired. Null when no date is set. */
  days: number | null;
}

const DAY_MS = 86_400_000;

/** A key is valid through its expiry date and counts as expired the day after. */
export function expiryStatus(expires: string | null, now: Date = new Date()): ExpiryStatus {
  if (!expires || !isRealDate(expires)) return { state: "none", days: null };
  const today = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());
  const days = Math.round((Date.parse(`${expires}T00:00:00Z`) - today) / DAY_MS);
  if (days < 0) return { state: "expired", days };
  return { state: days <= EXPIRY_WARNING_DAYS ? "soon" : "ok", days };
}

/** Ids whose keys are expired or expiring soon, soonest first. For summaries and checks. */
export function attentionList(file: KeyMetaFile, now: Date = new Date()): { id: string; state: ExpiryState; days: number }[] {
  return Object.entries(file.keys)
    .map(([id, meta]) => ({ id, ...expiryStatus(meta.expires, now) }))
    .filter((row): row is { id: string; state: ExpiryState; days: number } => (row.state === "expired" || row.state === "soon") && row.days !== null)
    .sort((a, b) => a.days - b.days);
}
