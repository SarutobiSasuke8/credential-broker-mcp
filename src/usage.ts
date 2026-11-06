import { open, stat } from "node:fs/promises";

/**
 * Usage summary for the key manager, built from the content-free audit log:
 * when each credential was last used, by whom, and how its recent requests
 * ended. Nothing here reads request or response content, because the audit
 * never records any.
 */

export interface UsageSummary {
  lastAt: string | null;
  lastAgent: string | null;
  /** Counts of finished requests in the window. */
  succeeded: number;
  denied: number;
  failed: number;
}

export const USAGE_WINDOW_DAYS = 30;
/** Only the tail of a long audit file is read. */
export const MAX_AUDIT_BYTES = 4 * 1024 * 1024;

const TERMINAL = new Set(["succeeded", "denied", "failed", "indeterminate"]);

interface Line {
  at?: unknown;
  agentId?: unknown;
  credentialId?: unknown;
  method?: unknown;
  outcome?: unknown;
}

/** Records that are not upstream requests (key requests, reloads). */
const NON_REQUEST_METHODS = new Set(["REQUEST_KEY", "RELOAD"]);

export function summarizeUsage(lines: Iterable<string>, now: Date = new Date()): Map<string, UsageSummary> {
  const cutoff = now.getTime() - USAGE_WINDOW_DAYS * 86_400_000;
  const out = new Map<string, UsageSummary>();
  for (const text of lines) {
    if (!text.trim()) continue;
    let line: Line;
    try {
      line = JSON.parse(text) as Line;
    } catch {
      continue;
    }
    if (typeof line.credentialId !== "string" || typeof line.outcome !== "string" || typeof line.at !== "string") continue;
    if (typeof line.method === "string" && NON_REQUEST_METHODS.has(line.method)) continue;
    if (!TERMINAL.has(line.outcome)) continue;
    const when = Date.parse(line.at);
    if (Number.isNaN(when)) continue;
    const entry = out.get(line.credentialId) ?? { lastAt: null, lastAgent: null, succeeded: 0, denied: 0, failed: 0 };
    if (entry.lastAt === null || when > Date.parse(entry.lastAt)) {
      entry.lastAt = line.at;
      entry.lastAgent = typeof line.agentId === "string" ? line.agentId : null;
    }
    if (when >= cutoff) {
      if (line.outcome === "succeeded") entry.succeeded += 1;
      else if (line.outcome === "denied") entry.denied += 1;
      else entry.failed += 1;
    }
    out.set(line.credentialId, entry);
  }
  return out;
}

/** Reads at most the last MAX_AUDIT_BYTES of the audit file. A missing file is empty. */
export async function readAuditLines(file: string): Promise<string[]> {
  let size: number;
  try {
    size = (await stat(file)).size;
  } catch {
    return [];
  }
  const start = Math.max(0, size - MAX_AUDIT_BYTES);
  const handle = await open(file, "r");
  try {
    const buffer = Buffer.alloc(size - start);
    await handle.read(buffer, 0, buffer.length, start);
    const lines = buffer.toString("utf8").split("\n");
    // A partial first line is dropped when the file was cut mid-record.
    return start > 0 ? lines.slice(1) : lines;
  } finally {
    await handle.close();
  }
}
