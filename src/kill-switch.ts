import { readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";

import { z } from "zod";

/**
 * Operator pause ("panic button"). One small JSON file, written by the key
 * manager or the pause command and read by the broker before every request.
 *
 * - Scope: everything, one agent, or one credential.
 * - Fail closed: a missing file means nothing is paused, but a file that
 *   exists and cannot be read or understood pauses everything, so a half
 *   written or corrupted switch can never silently re-open access.
 * - Re-read on every request, so a pause takes effect mid-flight with no
 *   restart, exactly like editing the approvals file.
 * - It only ever narrows access. It cannot grant anything.
 * - Tamper evidence: a pause is never released by the file going away. Resuming
 *   writes an explicit record ("resumed") into a valid file, and a running
 *   broker that sees an active pause vanish without that record keeps the pause.
 *   This catches accidents and casual tampering. A hostile process running as
 *   the same OS user can still forge a valid file; the real protection against
 *   that is the secure-launch profile in SECURITY.md.
 */

export const MAX_PAUSE_REASON = 200;

/** The pause file sits beside the policy unless BROKER_PAUSE_FILE says otherwise. */
export function pauseFilePath(policyFile: string, override: string | undefined = process.env.BROKER_PAUSE_FILE): string {
  return override ? resolve(override) : join(dirname(resolve(policyFile)), "pause.json");
}

const entrySchema = z.object({
  at: z.string(),
  reason: z.string().max(MAX_PAUSE_REASON).default(""),
});

/** Written when a pause is lifted on purpose. Content-free: a scope and a time. */
const resumeRecordSchema = z.object({ scope: z.string().max(100), at: z.string() });
const MAX_RESUME_RECORDS = 50;

const stateSchema = z.object({
  version: z.literal(1),
  /** Counts every write, so a stale or replaced file is easy to spot. */
  revision: z.number().int().nonnegative().default(0),
  all: entrySchema.nullable().default(null),
  agents: z.record(z.string(), entrySchema).default({}),
  credentials: z.record(z.string(), entrySchema).default({}),
  resumed: z.array(resumeRecordSchema).max(MAX_RESUME_RECORDS).default([]),
});

export type PauseEntry = z.infer<typeof entrySchema>;
export type PauseState = z.infer<typeof stateSchema>;

export const EMPTY_PAUSE: PauseState = { version: 1, revision: 0, all: null, agents: {}, credentials: {}, resumed: [] };

export type PauseScope = { kind: "all" } | { kind: "agent"; id: string } | { kind: "credential"; id: string };

export type PauseCheck =
  | { paused: false }
  | { paused: true; scope: "all" | "agent" | "credential" | "unreadable"; reason: string };

export type ParsedPause = { ok: true; state: PauseState } | { ok: false };

export function parsePauseState(text: string): ParsedPause {
  try {
    return { ok: true, state: stateSchema.parse(JSON.parse(text)) };
  } catch {
    return { ok: false };
  }
}

export function serializePauseState(state: PauseState): string {
  return `${JSON.stringify(state, null, 2)}\n`;
}

/** A stable text key for a scope, used in resume records and audit lines. */
export function scopeKey(scope: PauseScope): string {
  return scope.kind === "all" ? "all" : `${scope.kind}:${scope.id}`;
}

function entryFor(state: PauseState, scope: PauseScope): PauseEntry | null {
  if (scope.kind === "all") return state.all;
  return (scope.kind === "agent" ? state.agents : state.credentials)[scope.id] ?? null;
}

/**
 * Returns a new state with the scope paused or resumed. Every resume appends a
 * resume record, even when the file showed nothing paused: that record is what
 * lets a running broker tell an operator's resume from a deleted or replaced
 * file, and it is how the operator releases a pause the broker is holding.
 */
export function applyPause(state: PauseState, scope: PauseScope, active: boolean, reason: string, now: Date = new Date()): PauseState {
  const at = now.toISOString();
  const entry: PauseEntry = { at, reason: reason.trim().slice(0, MAX_PAUSE_REASON) };
  const resumed = active ? state.resumed : [...state.resumed, { scope: scopeKey(scope), at }].slice(-MAX_RESUME_RECORDS);
  const base = { ...state, revision: state.revision + 1, resumed };
  if (scope.kind === "all") return { ...base, all: active ? entry : null };
  const key = scope.kind === "agent" ? "agents" : "credentials";
  const next = { ...state[key] };
  if (active) next[scope.id] = entry;
  else delete next[scope.id];
  return { ...base, [key]: next };
}

function activeScopes(state: PauseState): { scope: PauseScope; entry: PauseEntry }[] {
  const out: { scope: PauseScope; entry: PauseEntry }[] = [];
  if (state.all) out.push({ scope: { kind: "all" }, entry: state.all });
  for (const [id, entry] of Object.entries(state.agents)) out.push({ scope: { kind: "agent", id }, entry });
  for (const [id, entry] of Object.entries(state.credentials)) out.push({ scope: { kind: "credential", id }, entry });
  return out;
}

export interface Reconciled {
  /** What the broker enforces: the new file, plus any pause the file dropped without a resume record. */
  effective: PauseState;
  /** The scopes that were kept paused because no matching resume record exists. */
  held: PauseScope[];
}

/**
 * Compares the pause state the broker last enforced with a freshly read, valid
 * file. A pause that is gone from the file is only released when the file
 * carries a resume record for that scope dated at or after the pause itself.
 */
export function reconcilePause(previous: PauseState | null, next: PauseState): Reconciled {
  if (!previous) return { effective: next, held: [] };
  const held: PauseScope[] = [];
  let effective = next;
  for (const { scope, entry } of activeScopes(previous)) {
    if (entryFor(next, scope) !== null) continue;
    const pausedAt = Date.parse(entry.at);
    const released = next.resumed.some((r) => r.scope === scopeKey(scope) && Date.parse(r.at) >= pausedAt);
    if (released) continue;
    held.push(scope);
    if (scope.kind === "all") {
      effective = { ...effective, all: entry };
    } else {
      const key = scope.kind === "agent" ? "agents" : "credentials";
      effective = { ...effective, [key]: { ...effective[key], [scope.id]: entry } };
    }
  }
  return { effective, held };
}

export function checkPause(state: PauseState, agentId: string, credentialId: string): PauseCheck {
  if (state.all) return { paused: true, scope: "all", reason: state.all.reason };
  const agent = state.agents[agentId];
  if (agent) return { paused: true, scope: "agent", reason: agent.reason };
  const credential = state.credentials[credentialId];
  if (credential) return { paused: true, scope: "credential", reason: credential.reason };
  return { paused: false };
}

export function anyPauseActive(state: PauseState): boolean {
  return state.all !== null || Object.keys(state.agents).length > 0 || Object.keys(state.credentials).length > 0;
}

export interface PauseGuard {
  check(agentId: string, credentialId: string): Promise<PauseCheck>;
}

/** Something the broker noticed about the pause file that the operator should know. */
export interface PauseFileEvent {
  kind: "missing" | "invalid" | "held";
  /** Content-free, fixed wording. Never includes the operator's reason. */
  detail: string;
}

/**
 * Reads the pause file on every call. See the fail-closed rules above. It also
 * remembers the pause it last enforced, so a pause that disappears from the
 * file without a resume record stays in force and is reported once.
 */
export class FilePauseGuard implements PauseGuard {
  private enforced: PauseState | null = null;
  private reported: string | null = null;

  public constructor(
    private readonly file: string,
    private readonly onEvent?: (event: PauseFileEvent) => void | Promise<void>,
  ) {}

  private async report(key: string, event: PauseFileEvent): Promise<void> {
    if (this.reported === key) return;
    this.reported = key;
    try {
      await this.onEvent?.(event);
    } catch {
      // A failing audit write must never turn into an open door.
    }
  }

  public async check(agentId: string, credentialId: string): Promise<PauseCheck> {
    let text: string;
    try {
      text = await readFile(this.file, "utf8");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") {
        if (this.enforced && anyPauseActive(this.enforced)) {
          await this.report("missing", {
            kind: "missing",
            detail: "pause file went missing while a pause was active; the last pause stays in force until a valid resume is written",
          });
          return checkPause(this.enforced, agentId, credentialId);
        }
        return { paused: false };
      }
      return { paused: true, scope: "unreadable", reason: "The pause file could not be read." };
    }
    const parsed = parsePauseState(text);
    if (!parsed.ok) {
      await this.report("invalid", { kind: "invalid", detail: "pause file is not valid; all access is paused until a valid file is written" });
      return { paused: true, scope: "unreadable", reason: "The pause file is not valid." };
    }
    const { effective, held } = reconcilePause(this.enforced, parsed.state);
    this.enforced = effective;
    if (held.length > 0) {
      await this.report(`held:${held.map(scopeKey).sort().join(",")}`, {
        kind: "held",
        detail: "pause file changed without a resume record; the pause stays in force until a valid resume is written",
      });
    } else {
      this.reported = null;
    }
    return checkPause(effective, agentId, credentialId);
  }
}
