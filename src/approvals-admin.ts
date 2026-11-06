import { randomBytes } from "node:crypto";

/**
 * Operator-side editing of the approvals file the broker already reads. The
 * file format is unchanged, so existing hand-written approvals keep working:
 * [{ id, agent_id, credential_id, operation_id, expires_at, revoked? }]
 * Unknown fields on existing entries are preserved. Nothing here can approve
 * anything the policy does not already mark as requiring approval.
 */

export interface ApprovalEntry {
  id: string;
  agent_id: string;
  credential_id: string;
  operation_id: string;
  expires_at: string;
  revoked?: boolean;
  [extra: string]: unknown;
}

export type ApprovalState = "active" | "expired" | "revoked";

export const MIN_APPROVAL_MINUTES = 1;
export const MAX_APPROVAL_MINUTES = 24 * 60;

export function parseApprovals(text: string | null): ApprovalEntry[] {
  if (!text) return [];
  try {
    const parsed: unknown = JSON.parse(text);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((entry): entry is ApprovalEntry => {
      if (typeof entry !== "object" || entry === null) return false;
      const raw = entry as Record<string, unknown>;
      return ["id", "agent_id", "credential_id", "operation_id", "expires_at"].every((key) => typeof raw[key] === "string");
    });
  } catch {
    return [];
  }
}

export function serializeApprovals(entries: ApprovalEntry[]): string {
  return `${JSON.stringify(entries, null, 2)}\n`;
}

export function approvalState(entry: ApprovalEntry, now: Date = new Date()): ApprovalState {
  if (entry.revoked === true) return "revoked";
  const expires = Date.parse(entry.expires_at);
  return Number.isNaN(expires) || expires <= now.getTime() ? "expired" : "active";
}

export interface NewApproval {
  agentId: string;
  credentialId: string;
  operationId: string;
  minutes: number;
}

/** Returns the new list and the created entry. Throws on an out-of-range lifetime. */
export function createApproval(entries: ApprovalEntry[], input: NewApproval, now: Date = new Date()): { entries: ApprovalEntry[]; created: ApprovalEntry } {
  if (!Number.isInteger(input.minutes) || input.minutes < MIN_APPROVAL_MINUTES || input.minutes > MAX_APPROVAL_MINUTES) {
    throw new Error(`Choose a lifetime between ${MIN_APPROVAL_MINUTES} minute and ${MAX_APPROVAL_MINUTES / 60} hours.`);
  }
  const created: ApprovalEntry = {
    id: `appr-${randomBytes(9).toString("hex")}`,
    agent_id: input.agentId,
    credential_id: input.credentialId,
    operation_id: input.operationId,
    expires_at: new Date(now.getTime() + input.minutes * 60_000).toISOString(),
    revoked: false,
  };
  return { entries: [...entries, created], created };
}

/** Marks an approval revoked. Returns null if the id is unknown. */
export function revokeApproval(entries: ApprovalEntry[], id: string): ApprovalEntry[] | null {
  if (!entries.some((entry) => entry.id === id)) return null;
  return entries.map((entry) => (entry.id === id ? { ...entry, revoked: true } : entry));
}

/** Drops entries that expired or were revoked more than `days` ago, to keep the file short. */
export function pruneApprovals(entries: ApprovalEntry[], days: number, now: Date = new Date()): ApprovalEntry[] {
  const cutoff = now.getTime() - days * 86_400_000;
  return entries.filter((entry) => {
    const expires = Date.parse(entry.expires_at);
    return approvalState(entry, now) === "active" || Number.isNaN(expires) || expires >= cutoff;
  });
}
