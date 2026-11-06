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

const stateSchema = z.object({
  version: z.literal(1),
  all: entrySchema.nullable().default(null),
  agents: z.record(z.string(), entrySchema).default({}),
  credentials: z.record(z.string(), entrySchema).default({}),
});

export type PauseEntry = z.infer<typeof entrySchema>;
export type PauseState = z.infer<typeof stateSchema>;

export const EMPTY_PAUSE: PauseState = { version: 1, all: null, agents: {}, credentials: {} };

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

/** Returns a new state with the scope paused or resumed. */
export function applyPause(state: PauseState, scope: PauseScope, active: boolean, reason: string, now: Date = new Date()): PauseState {
  const entry: PauseEntry = { at: now.toISOString(), reason: reason.trim().slice(0, MAX_PAUSE_REASON) };
  if (scope.kind === "all") return { ...state, all: active ? entry : null };
  const key = scope.kind === "agent" ? "agents" : "credentials";
  const next = { ...state[key] };
  if (active) next[scope.id] = entry;
  else delete next[scope.id];
  return { ...state, [key]: next };
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

/** Reads the pause file on every call. See the fail-closed rules above. */
export class FilePauseGuard implements PauseGuard {
  public constructor(private readonly file: string) {}

  public async check(agentId: string, credentialId: string): Promise<PauseCheck> {
    let text: string;
    try {
      text = await readFile(this.file, "utf8");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return { paused: false };
      return { paused: true, scope: "unreadable", reason: "The pause file could not be read." };
    }
    const parsed = parsePauseState(text);
    if (!parsed.ok) return { paused: true, scope: "unreadable", reason: "The pause file is not valid." };
    return checkPause(parsed.state, agentId, credentialId);
  }
}
