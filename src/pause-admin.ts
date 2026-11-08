import { randomBytes } from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

import { z } from "zod";

import { AuditLogger } from "./audit.js";
import { applyPause, EMPTY_PAUSE, MAX_PAUSE_REASON, parsePauseState, serializePauseState } from "./kill-switch.js";

import type { AuditRecord } from "./audit.js";
import type { PauseScope, PauseState } from "./kill-switch.js";

/**
 * The one place that changes the pause file, shared by the key manager and the
 * pause command so both behave the same way:
 *
 * - It never deletes the file. Resuming writes an explicit "resumed" record, so
 *   a running broker can tell a resume from a file that was removed.
 * - Every change appends one content-free audit line: which scope, on or off,
 *   from where, and when. The operator's reason is kept in the pause file for
 *   the operator and is never written to the audit or shown to an agent.
 */

const ID = /^[a-z0-9][a-z0-9._-]{1,63}$/u;

export const PAUSE_WORD = "PAUSE";
export const RESUME_WORD = "RESUME";

export type PauseSource = "page" | "cli";

export const pauseRequestSchema = z.object({
  scope: z.discriminatedUnion("kind", [
    z.object({ kind: z.literal("all") }),
    z.object({ kind: z.literal("agent"), id: z.string().regex(ID) }),
    z.object({ kind: z.literal("credential"), id: z.string().regex(ID) }),
  ]),
  active: z.boolean(),
  reason: z.string().max(MAX_PAUSE_REASON).default(""),
  /** The word typed in the page's confirmation box. Required for the global switch. */
  confirm: z.string().max(40).optional(),
  /** True when the page is taking back a pause it made seconds ago. Only changes the audit wording. */
  undo: z.boolean().default(false),
});

export type PauseRequest = z.infer<typeof pauseRequestSchema>;

/** Case-insensitive, ignores surrounding space. This guards against accidents in the page, not against an attacker. */
export function confirmationMatches(typed: string | undefined, active: boolean): boolean {
  return (typed ?? "").trim().toUpperCase() === (active ? PAUSE_WORD : RESUME_WORD);
}

export function describeScope(scope: PauseScope): string {
  return scope.kind === "all" ? "all agent access" : `${scope.kind} ${scope.id}`;
}

export async function readPauseFile(file: string): Promise<{ state: PauseState; exists: boolean; unreadable: boolean }> {
  let text: string;
  try {
    text = await readFile(file, "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return { state: EMPTY_PAUSE, exists: false, unreadable: false };
    return { state: EMPTY_PAUSE, exists: true, unreadable: true };
  }
  const parsed = parsePauseState(text);
  return parsed.ok ? { state: parsed.state, exists: true, unreadable: false } : { state: EMPTY_PAUSE, exists: true, unreadable: true };
}

/**
 * Atomic replace through a fresh temp file in the same folder ("wx" refuses
 * to follow anything already there). Nothing here ever removes the pause file.
 * The 0600 mode applies on POSIX only; Windows uses the folder's ACLs.
 */
export async function writePauseFile(file: string, state: PauseState): Promise<void> {
  await mkdir(dirname(file), { recursive: true });
  const temp = `${file}.tmp-${process.pid}-${randomBytes(4).toString("hex")}`;
  await writeFile(temp, serializePauseState(state), { encoding: "utf8", mode: 0o600, flag: "wx" });
  await rename(temp, file);
}

/**
 * The pause state the audit log can prove: for each scope, the last PAUSE or
 * RESUME line wins. Used to seed a freshly started broker, so deleting or
 * replacing the file and restarting the broker does not quietly resume.
 */
export function pauseStateFromAudit(lines: Iterable<string>): PauseState {
  let state = EMPTY_PAUSE;
  for (const text of lines) {
    if (!text.trim()) continue;
    let line: { method?: unknown; pathname?: unknown; at?: unknown };
    try {
      line = JSON.parse(text) as typeof line;
    } catch {
      continue;
    }
    if ((line.method !== "PAUSE" && line.method !== "RESUME") || typeof line.pathname !== "string" || typeof line.at !== "string") continue;
    const scope = scopeFromPath(line.pathname);
    if (!scope) continue;
    const at = new Date(line.at);
    if (Number.isNaN(at.getTime())) continue;
    state = applyPause(state, scope, line.method === "PAUSE", "", at);
  }
  return { ...state, revision: 0, resumed: [] };
}

function scopeFromPath(pathname: string): PauseScope | null {
  if (pathname === "/all") return { kind: "all" };
  const [, kind, id] = pathname.split("/");
  if ((kind === "agent" || kind === "credential") && id && ID.test(id)) return { kind, id };
  return null;
}

export function pauseAuditRecord(scope: PauseScope, active: boolean, source: PauseSource, undo: boolean): AuditRecord {
  const path = scope.kind === "all" ? "/all" : `/${scope.kind}/${scope.id}`;
  return {
    traceId: `pause-${Date.now().toString(36)}`,
    agentId: "operator",
    credentialId: "-",
    method: active ? "PAUSE" : "RESUME",
    host: "broker.local",
    pathname: path,
    outcome: "succeeded",
    detail: `${source}${undo ? " undo" : ""}`,
  };
}

export interface PauseChangeResult {
  before: PauseState;
  after: PauseState;
  /** False when the scope was already in the requested state. */
  changed: boolean;
  /** The file could not be read before this change, so it was rewritten from a clean state. */
  repaired: boolean;
}

export interface PauseChangeOptions {
  file: string;
  /** Null skips the audit line (tests only). */
  auditFile: string | null;
  source: PauseSource;
  now?: Date;
}

export async function changePause(options: PauseChangeOptions, request: Pick<PauseRequest, "scope" | "active" | "reason" | "undo">): Promise<PauseChangeResult> {
  const current = await readPauseFile(options.file);
  const before = current.state;
  // An unreadable file is replaced by a fresh valid one. While it was
  // unreadable every broker treated everything as paused, so the repair keeps
  // everything paused unless this very request is the explicit resume of all;
  // that resume carries its record, which is what releases a holding broker.
  const resumingAll = request.scope.kind === "all" && !request.active;
  let after = applyPause(before, request.scope, request.active, request.reason, options.now);
  const keepAllPaused = current.unreadable && !resumingAll;
  if (keepAllPaused) after = applyPause(after, { kind: "all" }, true, "", options.now);
  await writePauseFile(options.file, after);
  if (options.auditFile) {
    const audit = new AuditLogger(options.auditFile);
    await audit.write(pauseAuditRecord(request.scope, request.active, options.source, request.undo));
    if (keepAllPaused) await audit.write({ ...pauseAuditRecord({ kind: "all" }, true, options.source, false), detail: `${options.source} repair` });
  }
  const changed = request.active ? !wasActive(before, request.scope) : wasActive(before, request.scope) || current.unreadable;
  return { before, after, changed, repaired: current.unreadable };
}

function wasActive(state: PauseState, scope: PauseScope): boolean {
  if (scope.kind === "all") return state.all !== null;
  return (scope.kind === "agent" ? state.agents : state.credentials)[scope.id] !== undefined;
}

export function describeState(state: PauseState): string[] {
  const lines: string[] = [];
  const why = (reason: string): string => (reason ? `: ${reason}` : "");
  if (state.all) lines.push(`ALL agent access is paused since ${state.all.at}${why(state.all.reason)}`);
  for (const [id, entry] of Object.entries(state.agents)) lines.push(`Agent ${id} is paused since ${entry.at}${why(entry.reason)}`);
  for (const [id, entry] of Object.entries(state.credentials)) lines.push(`Credential ${id} is paused since ${entry.at}${why(entry.reason)}`);
  return lines.length > 0 ? lines : ["Nothing is paused."];
}
