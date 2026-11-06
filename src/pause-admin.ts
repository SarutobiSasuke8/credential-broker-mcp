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

/** Atomic replace through a temp file in the same folder. Nothing here ever removes the pause file. */
export async function writePauseFile(file: string, state: PauseState): Promise<void> {
  await mkdir(dirname(file), { recursive: true });
  const temp = `${file}.tmp-${process.pid}`;
  await writeFile(temp, serializePauseState(state), { encoding: "utf8", mode: 0o600 });
  await rename(temp, file);
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
  // An unreadable file is replaced by a fresh valid one. A resume of everything
  // then carries its resume record, which is what releases a broker that was
  // holding the pause. A narrower pause on top of an unreadable file keeps the
  // broker closed (the file is valid again but "all" is not resumed).
  const after = applyPause(before, request.scope, request.active, request.reason, options.now);
  await writePauseFile(options.file, after);
  if (options.auditFile) {
    await new AuditLogger(options.auditFile).write(pauseAuditRecord(request.scope, request.active, options.source, request.undo));
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
