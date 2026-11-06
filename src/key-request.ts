import { spawn } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { z } from "zod";

/**
 * Lets an agent ask the operator for a key. The broker opens the key manager
 * in the operator's browser, pre-filled with the credential name and the
 * reason. Nothing secret crosses this boundary in either direction:
 *
 * - The agent supplies only a short name, a reason and an optional provider.
 *   It never receives the page address, the session token or any value.
 * - The base URL, key style and header name come from the broker's own table
 *   of known providers. An agent cannot steer a key to a host of its choosing.
 * - The operator alone decides whether anything is added and who may use it.
 *
 * The tool is opt-in per process (BROKER_ALLOW_KEY_REQUESTS=1) and rate
 * limited, so a misbehaving agent cannot flood the operator with windows.
 */

export const KEY_REQUEST_ID = /^[a-z0-9][a-z0-9._-]{1,63}$/u;
export const MAX_REASON_LENGTH = 200;

export const keyRequestInputSchema = z.object({
  credential: z.string().regex(KEY_REQUEST_ID, "Use 2 to 64 lowercase letters, digits, dots, dashes or underscores."),
  reason: z.string().trim().min(3).max(MAX_REASON_LENGTH),
  provider: z.string().regex(KEY_REQUEST_ID).optional(),
});

export interface KeyRequest {
  credentialId: string;
  reason: string;
  requestedBy: string;
  provider?: string;
}

export interface KeyRequestLauncher {
  launch(request: KeyRequest): void | Promise<void>;
}

export type KeyRequestOutcome =
  | { status: "opened" }
  | { status: "rate_limited"; retryAfterSeconds: number }
  | { status: "unavailable"; message: string };

export interface KeyRequesterOptions {
  launcher: KeyRequestLauncher;
  now?: () => number;
  /** Minimum gap between windows for the same credential. */
  perCredentialMs?: number;
  /** Most windows the process may open in `windowMs`. */
  maxPerWindow?: number;
  windowMs?: number;
}

export class KeyRequester {
  private readonly launcher: KeyRequestLauncher;
  private readonly now: () => number;
  private readonly perCredentialMs: number;
  private readonly maxPerWindow: number;
  private readonly windowMs: number;
  private readonly lastByCredential = new Map<string, number>();
  private opened: number[] = [];

  public constructor(options: KeyRequesterOptions) {
    this.launcher = options.launcher;
    this.now = options.now ?? Date.now;
    this.perCredentialMs = options.perCredentialMs ?? 10 * 60_000;
    this.maxPerWindow = options.maxPerWindow ?? 5;
    this.windowMs = options.windowMs ?? 60 * 60_000;
  }

  public async request(request: KeyRequest): Promise<KeyRequestOutcome> {
    const now = this.now();
    this.opened = this.opened.filter((at) => now - at < this.windowMs);

    const last = this.lastByCredential.get(request.credentialId);
    if (last !== undefined && now - last < this.perCredentialMs) {
      return { status: "rate_limited", retryAfterSeconds: Math.ceil((this.perCredentialMs - (now - last)) / 1000) };
    }
    const oldest = this.opened[0];
    if (this.opened.length >= this.maxPerWindow && oldest !== undefined) {
      return { status: "rate_limited", retryAfterSeconds: Math.ceil((this.windowMs - (now - oldest)) / 1000) };
    }

    try {
      await this.launcher.launch(request);
    } catch (error) {
      return { status: "unavailable", message: error instanceof Error ? error.message : "Could not open the key manager." };
    }
    this.lastByCredential.set(request.credentialId, now);
    this.opened.push(now);
    return { status: "opened" };
  }
}

/**
 * Starts the key manager as a detached process that opens the operator's
 * browser. The request travels in an environment variable the child reads
 * and validates; the agent never sees the resulting page address.
 */
export function spawnKeyManagerLauncher(): KeyRequestLauncher {
  const entry = join(dirname(fileURLToPath(import.meta.url)), "keys-ui.js");
  return {
    launch(request: KeyRequest): void {
      const child = spawn(process.execPath, [entry], {
        detached: true,
        stdio: "ignore",
        env: { ...process.env, BROKER_KEYS_REQUEST: JSON.stringify(request) },
      });
      child.on("error", () => undefined);
      child.unref();
    },
  };
}

export interface KeyRequestToolDeps {
  requester: KeyRequester;
  agentId: string;
  /** True when the credential is in the policy and a key is already available. */
  isProvisioned(credentialId: string): boolean;
  recordAudit(credentialId: string, detail: string): Promise<void>;
}

export interface KeyRequestToolResult {
  isError: boolean;
  payload: Record<string, unknown>;
}

/** The tool body, kept separate from MCP wiring so it can be tested directly. */
export async function handleKeyRequest(deps: KeyRequestToolDeps, rawInput: unknown): Promise<KeyRequestToolResult> {
  const input = keyRequestInputSchema.parse(rawInput);
  if (deps.isProvisioned(input.credential)) {
    await deps.recordAudit(input.credential, "key request skipped: already provisioned");
    return {
      isError: false,
      payload: { status: "already_provisioned", message: `A key for '${input.credential}' is already available to this agent.` },
    };
  }
  const outcome = await deps.requester.request({
    credentialId: input.credential,
    reason: input.reason,
    requestedBy: deps.agentId,
    ...(input.provider ? { provider: input.provider } : {}),
  });
  await deps.recordAudit(input.credential, `key request ${outcome.status}`);
  switch (outcome.status) {
    case "opened":
      return {
        isError: false,
        payload: {
          status: "opened",
          message:
            "The key manager has opened on the user's computer. Only the user decides whether to add a key and who may use it, " +
            "and this agent cannot see what they enter. Tell the user what you need it for, then wait. " +
            "The broker loads keys when it starts, so the MCP client must be restarted before a new key takes effect.",
        },
      };
    case "rate_limited":
      return {
        isError: true,
        payload: {
          status: "rate_limited",
          retry_after_seconds: outcome.retryAfterSeconds,
          message: "A key request was opened recently. Ask the user to check their open key manager window instead of requesting again.",
        },
      };
    case "unavailable":
      return { isError: true, payload: { status: "unavailable", message: outcome.message } };
  }
}
