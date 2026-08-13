import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";

import { RedactingAuditSink } from "./audit.js";
import { canonicalizeRequestUrl, serializeQuery } from "./canonical.js";
import { evaluate } from "./gateway.js";
import { SecretRedactor } from "./redact.js";
import { isMutationMethod } from "./types.js";

import type { AuditSink } from "./audit.js";
import type { BrokerPolicy, CredentialSpec, OperationGrant } from "./types.js";

/**
 * The BrokerEngine is the only path from an agent request to an upstream
 * call. It binds one authenticated principal at construction, resolves
 * secrets through a scoped provider, checks approvals at execution time,
 * records the full audit lifecycle, and passes every outbound string through
 * the central redactor. Raw injection and upstream execution are private:
 * no public consumer of this package can exercise a secret without policy,
 * principal, and audit.
 */

// ---------------------------------------------------------------------------
// Interfaces (issue #4: transport-independent engine seams)
// ---------------------------------------------------------------------------

export interface Clock {
  now(): Date;
}

export const SYSTEM_CLOCK: Clock = { now: () => new Date() };

/** Resolves secret material. Implementations must scope to one principal. */
export interface SecretProvider {
  /** Secret for a credential this provider is scoped to, else undefined. */
  getSecret(credentialId: string): string | undefined;
  /** Every secret value held, for building the redactor. Never exposed. */
  listSecretValues(): string[];
}

/**
 * Environment-backed secrets, scoped to the credentials one principal is
 * granted. Secrets for other principals' credentials are never loaded, so a
 * compromised session cannot reach them through any tool path. With
 * scrubEnv, every credential variable named in the policy is removed from
 * process.env after loading, so child processes and later code cannot read
 * them back.
 */
export class EnvSecretProvider implements SecretProvider {
  private readonly secrets = new Map<string, string>();

  public constructor(
    policy: BrokerPolicy,
    principalId: string,
    options: { env?: Record<string, string | undefined>; scrubEnv?: boolean } = {},
  ) {
    const env = options.env ?? process.env;
    const agent = policy.agents.get(principalId);
    for (const [credentialId, credential] of policy.credentials) {
      const granted = agent?.grants.has(credentialId) ?? false;
      const value = env[credential.envVar];
      if (granted && value) this.secrets.set(credentialId, value);
      if (options.scrubEnv) delete env[credential.envVar];
    }
  }

  public getSecret(credentialId: string): string | undefined {
    return this.secrets.get(credentialId);
  }

  public listSecretValues(): string[] {
    return [...this.secrets.values()];
  }
}

export interface ApprovalRecord {
  id: string;
  agentId: string;
  credentialId: string;
  operationId: string;
  /** ISO 8601 expiry. An unparseable or past expiry fails closed. */
  expiresAt: string;
  revoked?: boolean;
}

export interface ApprovalStore {
  get(approvalId: string): Promise<ApprovalRecord | undefined>;
}

export class InMemoryApprovalStore implements ApprovalStore {
  private readonly records = new Map<string, ApprovalRecord>();

  public put(record: ApprovalRecord): void {
    this.records.set(record.id, record);
  }

  public revoke(approvalId: string): void {
    const record = this.records.get(approvalId);
    if (record) record.revoked = true;
  }

  public async get(approvalId: string): Promise<ApprovalRecord | undefined> {
    return this.records.get(approvalId);
  }
}

/**
 * Approvals in a JSON file the operator writes:
 * [{"id": "...", "agent_id": "...", "credential_id": "...",
 *   "operation_id": "...", "expires_at": "2026-01-01T00:00:00Z",
 *   "revoked": false}]
 * The file is re-read on every check, so editing it revokes mid-flight.
 * A missing or unreadable file means no approvals exist: fail closed.
 */
export class FileApprovalStore implements ApprovalStore {
  public constructor(private readonly file: string) {}

  public async get(approvalId: string): Promise<ApprovalRecord | undefined> {
    let text: string;
    try {
      text = await readFile(this.file, "utf8");
    } catch {
      return undefined;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      return undefined;
    }
    if (!Array.isArray(parsed)) return undefined;
    for (const entry of parsed) {
      if (typeof entry !== "object" || entry === null) continue;
      const raw = entry as Record<string, unknown>;
      if (raw.id !== approvalId) continue;
      if (
        typeof raw.agent_id !== "string" ||
        typeof raw.credential_id !== "string" ||
        typeof raw.operation_id !== "string" ||
        typeof raw.expires_at !== "string"
      ) {
        return undefined;
      }
      return {
        id: approvalId,
        agentId: raw.agent_id,
        credentialId: raw.credential_id,
        operationId: raw.operation_id,
        expiresAt: raw.expires_at,
        revoked: raw.revoked === true,
      };
    }
    return undefined;
  }
}

// ---------------------------------------------------------------------------
// Engine request/result shapes
// ---------------------------------------------------------------------------

export interface EngineRequest {
  credentialId: string;
  method: string;
  url: string;
  body?: string;
  contentType?: string;
  approvalId?: string;
  idempotencyKey?: string;
}

export interface EngineDenied {
  kind: "denied";
  reason: string;
  decidingRule: { source: string; pattern: string } | null;
  traceId: string;
}

export interface EngineError {
  kind: "error";
  /** Stable category; raw upstream error text is never relayed to agents. */
  code: "timeout" | "redirect-refused" | "network-error" | "not-provisioned" | "internal";
  message: string;
  outcome: "failed" | "indeterminate";
  traceId: string;
}

export interface EngineSuccess {
  kind: "success";
  traceId: string;
  operationId: string;
  status: number;
  headers: Record<string, string>;
  truncated: boolean;
  /** Present only when the operation's response policy relays a body. */
  body?: string;
  bodyWithheldReason?: string;
}

export type EngineResult = EngineDenied | EngineError | EngineSuccess;

export interface ExplainResult {
  allowed: boolean;
  reason: string;
  decidingRule: { source: string; pattern: string } | null;
  operationId?: string;
  requiresApproval?: boolean;
  /** State of the supplied approval id, checked without any side effect. */
  approvalState?: "not-required" | "required" | "satisfied" | "missing" | "expired" | "revoked" | "mismatched";
}

export interface EngineOptions {
  policy: BrokerPolicy;
  /** Authenticated principal. Fixed for the engine's lifetime. */
  principalId: string;
  secrets: SecretProvider;
  audit: AuditSink;
  approvals?: ApprovalStore;
  clock?: Clock;
  fetchImpl?: typeof fetch;
  /** Upstream timeout in milliseconds. */
  timeoutMs?: number;
}

/** Response headers that are safe to relay. Everything else is dropped. */
const SAFE_RESPONSE_HEADERS = ["content-type", "content-length", "retry-after", "x-ratelimit-remaining"];

type ApprovalCheck =
  | { ok: true }
  | { ok: false; state: "missing" | "expired" | "revoked" | "mismatched"; reason: string };

export class BrokerEngine {
  private readonly policy: BrokerPolicy;
  private readonly principalId: string;
  private readonly secrets: SecretProvider;
  private readonly audit: AuditSink;
  private readonly approvals: ApprovalStore | undefined;
  private readonly clock: Clock;
  private readonly fetchImpl: typeof fetch;
  private readonly timeoutMs: number;
  public readonly redactor: SecretRedactor;

  public constructor(options: EngineOptions) {
    this.policy = options.policy;
    this.principalId = options.principalId;
    this.secrets = options.secrets;
    this.clock = options.clock ?? SYSTEM_CLOCK;
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.timeoutMs = options.timeoutMs ?? 15_000;
    this.approvals = options.approvals;
    this.redactor = new SecretRedactor(options.secrets.listSecretValues());
    // Every audit record passes through the redactor, whatever sink is used.
    this.audit = new RedactingAuditSink(options.audit, this.redactor);
    if (!this.policy.agents.has(this.principalId)) {
      throw new Error(`Principal '${this.principalId}' is not provisioned in the policy.`);
    }
  }

  public get principal(): string {
    return this.principalId;
  }

  /** Content-free preflight: decision plus approval requirement, no secret
   * acquisition, no upstream contact. */
  public async explain(request: EngineRequest): Promise<ExplainResult> {
    const decision = evaluate(this.policy, this.principalId, request.credentialId, {
      method: request.method,
      url: request.url,
      ...(request.body !== undefined ? { body: request.body } : {}),
      ...(request.contentType !== undefined ? { contentType: request.contentType } : {}),
    });
    const base: ExplainResult = {
      allowed: decision.allowed,
      reason: decision.reason,
      decidingRule: decision.decidingRule,
    };
    if (!decision.allowed || !decision.operation) return base;
    base.operationId = decision.operation.id;
    base.requiresApproval = decision.operation.requiresApproval;
    if (!decision.operation.requiresApproval) {
      base.approvalState = "not-required";
    } else if (request.approvalId === undefined) {
      base.approvalState = "required";
    } else {
      const check = await this.checkApproval(request.approvalId, request.credentialId, decision.operation);
      base.approvalState = check.ok ? "satisfied" : check.state;
    }
    return base;
  }

  /** Authorise, approve, execute, declassify, and audit one request. */
  public async execute(request: EngineRequest): Promise<EngineResult> {
    const traceId = randomUUID();
    const decision = evaluate(this.policy, this.principalId, request.credentialId, {
      method: request.method,
      url: request.url,
      ...(request.body !== undefined ? { body: request.body } : {}),
      ...(request.contentType !== undefined ? { contentType: request.contentType } : {}),
    });
    const auditBase = {
      traceId,
      agentId: this.principalId,
      credentialId: request.credentialId,
      method: request.method.toUpperCase(),
      host: decision.canonical ? new URL(decision.canonical.origin).host : "invalid",
      pathname: decision.canonical?.canonicalPath ?? "invalid",
      ...(decision.operation ? { operationId: decision.operation.id } : {}),
      ...(request.approvalId !== undefined ? { approvalId: request.approvalId } : {}),
      ...(request.idempotencyKey !== undefined ? { idempotencyKey: request.idempotencyKey } : {}),
    };
    await this.audit.write({ ...auditBase, outcome: "requested" });

    if (!decision.allowed || !decision.operation || !decision.credential || !decision.canonical) {
      await this.audit.write({ ...auditBase, outcome: "denied", detail: decision.reason });
      return { kind: "denied", reason: decision.reason, decidingRule: decision.decidingRule, traceId };
    }
    const operation = decision.operation;

    if (operation.requiresIdempotencyKey && !request.idempotencyKey) {
      const reason =
        `Operation '${operation.id}' requires an idempotency_key so a retry has a defined contract. ` +
        `Supply one and retry with the same key.`;
      await this.audit.write({ ...auditBase, outcome: "denied", detail: reason });
      return { kind: "denied", reason, decidingRule: { source: "operation-allow", pattern: operation.id }, traceId };
    }

    // Approval is checked here, at execution time, against the live store and
    // the injected clock. A grant loaded an hour ago proves nothing now.
    if (operation.requiresApproval) {
      if (request.approvalId === undefined) {
        const reason = `Operation '${operation.id}' requires an approval_id. None was supplied.`;
        await this.audit.write({ ...auditBase, outcome: "denied", detail: reason });
        return { kind: "denied", reason, decidingRule: { source: "operation-allow", pattern: operation.id }, traceId };
      }
      const check = await this.checkApproval(request.approvalId, request.credentialId, operation);
      if (!check.ok) {
        await this.audit.write({ ...auditBase, outcome: "denied", detail: check.reason });
        return {
          kind: "denied",
          reason: check.reason,
          decidingRule: { source: "operation-allow", pattern: operation.id },
          traceId,
        };
      }
      await this.audit.write({ ...auditBase, outcome: "approved" });
    }

    const mutation = isMutationMethod(request.method);
    const secret = this.secrets.getSecret(request.credentialId);
    if (!secret) {
      // The env var name is an operator detail; agents get the credential id only.
      const agentMessage = `Credential '${request.credentialId}' is not provisioned. Ask the operator to provide it.`;
      await this.audit.write({
        ...auditBase,
        outcome: "failed",
        detail: `Secret for '${request.credentialId}' (env ${decision.credential.envVar}) is not provisioned.`,
      });
      return { kind: "error", code: "not-provisioned", message: agentMessage, outcome: "failed", traceId };
    }

    // Rebuild the outbound URL from the authorised canonical value only, and
    // prove the rebuilt bytes canonicalise back to the same value.
    const outboundHref = decision.canonical.href;
    const roundTrip = canonicalizeRequestUrl(outboundHref);
    if (
      !roundTrip.ok ||
      roundTrip.request.origin !== decision.canonical.origin ||
      roundTrip.request.canonicalPath !== decision.canonical.canonicalPath ||
      serializeQuery(roundTrip.request.query) !== serializeQuery(decision.canonical.query)
    ) {
      const reason = "Outbound URL failed the canonical round-trip check. Refusing to send.";
      await this.audit.write({ ...auditBase, outcome: "failed", detail: reason });
      return { kind: "error", code: "internal", message: reason, outcome: "failed", traceId };
    }

    await this.audit.write({ ...auditBase, outcome: "executing" });

    const url = new URL(outboundHref);
    const headers = new Headers();
    headers.set("accept", "application/json, text/plain;q=0.9, */*;q=0.1");
    if (request.contentType) headers.set("content-type", request.contentType);
    this.injectCredential(decision.credential, secret, url, headers);

    let response: Response;
    try {
      response = await this.fetchImpl(url, {
        method: request.method.toUpperCase(),
        headers,
        ...(request.body !== undefined ? { body: request.body } : {}),
        // A redirect can point anywhere, including outside the credential's
        // base URL, and fetch would re-send our injected header there.
        redirect: "error",
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch (error) {
      // A dispatch failure on a mutation is indeterminate: the upstream may
      // have applied the change before the connection died.
      const outcome = mutation ? "indeterminate" : "failed";
      const code = classifyFetchError(error);
      await this.audit.write({ ...auditBase, outcome, detail: this.redactor.redactError(error) });
      return {
        kind: "error",
        code,
        message:
          `Upstream request did not complete (${code}). ` +
          `Raw upstream error text is not relayed; see the audit log (trace ${traceId}).` +
          (outcome === "indeterminate" ? " The mutation may or may not have been applied upstream." : ""),
        outcome,
        traceId,
      };
    }

    const { body, truncated } = await this.readBody(response, operation);

    const relayedHeaders: Record<string, string> = {};
    for (const name of SAFE_RESPONSE_HEADERS) {
      const value = response.headers.get(name);
      if (value !== null) relayedHeaders[name] = this.redactor.redact(value);
    }

    await this.audit.write({ ...auditBase, outcome: "succeeded", status: response.status });

    const result: EngineSuccess = {
      kind: "success",
      traceId,
      operationId: operation.id,
      status: response.status,
      headers: relayedHeaders,
      truncated,
    };
    if (!operation.responseBody) {
      result.bodyWithheldReason =
        "This operation relays response metadata only. Grant response_body: true in policy to relay bodies.";
      return result;
    }
    const contentType = (response.headers.get("content-type") ?? "").toLowerCase().split(";")[0]?.trim() ?? "";
    if (!operation.responseContentTypes.includes(contentType)) {
      result.bodyWithheldReason =
        `Upstream returned content type '${contentType || "unknown"}', which is not in this operation's ` +
        `response allowlist (${operation.responseContentTypes.join(", ")}). Body withheld.`;
      return result;
    }
    result.body = body;
    return result;
  }

  private injectCredential(credential: CredentialSpec, secret: string, url: URL, headers: Headers): void {
    switch (credential.kind) {
      case "bearer":
        headers.set("authorization", `Bearer ${secret}`);
        break;
      case "header":
        headers.set(credential.paramName ?? "x-api-key", secret);
        break;
      case "basic":
        headers.set("authorization", `Basic ${Buffer.from(secret, "utf8").toString("base64")}`);
        break;
      case "query":
        url.searchParams.set(credential.paramName ?? "api_key", secret);
        break;
    }
  }

  private async readBody(response: Response, operation: OperationGrant): Promise<{ body: string; truncated: boolean }> {
    const reader = response.body?.getReader();
    const chunks: Uint8Array[] = [];
    let received = 0;
    let truncated = false;
    if (reader) {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        received += value.byteLength;
        if (received > operation.maxResponseBytes) {
          truncated = true;
          chunks.push(value.subarray(0, value.byteLength - (received - operation.maxResponseBytes)));
          await reader.cancel();
          break;
        }
        chunks.push(value);
      }
    }
    const raw = Buffer.concat(chunks).toString("utf8");
    const body = truncated ? this.redactor.redactTruncated(raw) : this.redactor.redact(raw);
    return { body, truncated };
  }

  private async checkApproval(
    approvalId: string,
    credentialId: string,
    operation: OperationGrant,
  ): Promise<ApprovalCheck> {
    if (!this.approvals) {
      return {
        ok: false,
        state: "missing",
        reason: `Operation '${operation.id}' requires approval, but no approval store is configured. Failing closed.`,
      };
    }
    const record = await this.approvals.get(approvalId);
    if (!record) {
      return { ok: false, state: "missing", reason: `Approval '${approvalId}' does not exist.` };
    }
    if (record.revoked) {
      return { ok: false, state: "revoked", reason: `Approval '${approvalId}' has been revoked.` };
    }
    if (
      record.agentId !== this.principalId ||
      record.credentialId !== credentialId ||
      record.operationId !== operation.id
    ) {
      return {
        ok: false,
        state: "mismatched",
        reason:
          `Approval '${approvalId}' is bound to a different principal, credential, or operation. ` +
          `Approvals are not transferable.`,
      };
    }
    const expiresAt = Date.parse(record.expiresAt);
    if (Number.isNaN(expiresAt) || expiresAt <= this.clock.now().getTime()) {
      return { ok: false, state: "expired", reason: `Approval '${approvalId}' has expired.` };
    }
    return { ok: true };
  }
}

function classifyFetchError(error: unknown): "timeout" | "redirect-refused" | "network-error" {
  if (error instanceof Error) {
    if (error.name === "TimeoutError" || error.name === "AbortError") return "timeout";
    const chain = `${error.message} ${error.cause instanceof Error ? error.cause.message : ""}`.toLowerCase();
    if (chain.includes("redirect")) return "redirect-refused";
  }
  return "network-error";
}
