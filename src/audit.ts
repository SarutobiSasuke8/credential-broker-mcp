import { appendFile, mkdir } from "node:fs/promises";
import path from "node:path";

import type { SecretRedactor } from "./redact.js";

/**
 * Lifecycle states for one brokered request, linked by traceId:
 * requested -> denied, or requested -> approved? -> executing ->
 * succeeded | failed | indeterminate. "indeterminate" records a mutation
 * whose upstream effect is unknown (the request may have been applied).
 */
export type AuditOutcome =
  | "requested"
  | "approved"
  | "denied"
  | "executing"
  | "succeeded"
  | "failed"
  | "indeterminate";

/**
 * Content-free audit record. The canonical path is recorded; the query
 * string, request body, and response body are deliberately not, since they
 * may carry secrets or personal data. The audit answers "who reached what,
 * when, with what outcome", never "what did they see".
 */
export interface AuditRecord {
  traceId: string;
  agentId: string;
  credentialId: string;
  operationId?: string;
  method: string;
  host: string;
  pathname: string;
  outcome: AuditOutcome;
  status?: number;
  approvalId?: string;
  idempotencyKey?: string;
  detail?: string;
}

export interface AuditSink {
  write(record: AuditRecord): Promise<void>;
}

export class AuditLogger implements AuditSink {
  public constructor(private readonly file: string) {}

  public async write(record: AuditRecord): Promise<void> {
    await mkdir(path.dirname(this.file), { recursive: true });
    await appendFile(this.file, `${JSON.stringify({ at: new Date().toISOString(), ...record })}\n`, "utf8");
  }
}

/** Drops records; used when auditing is disabled or in tests. */
export class NullAuditLogger implements AuditSink {
  public async write(): Promise<void> {
    // intentionally empty
  }
}

/** Collects records in memory; used by tests to assert the state sequence. */
export class MemoryAuditSink implements AuditSink {
  public readonly records: AuditRecord[] = [];

  public async write(record: AuditRecord): Promise<void> {
    this.records.push(record);
  }
}

/**
 * Wraps any sink so every string field is passed through the central
 * redactor before it is durably recorded. Audit files must never hold a
 * recoverable secret representation.
 */
export class RedactingAuditSink implements AuditSink {
  public constructor(
    private readonly inner: AuditSink,
    private readonly redactor: SecretRedactor,
  ) {}

  public async write(record: AuditRecord): Promise<void> {
    const clean: AuditRecord = { ...record };
    clean.host = this.redactor.redact(clean.host);
    clean.pathname = this.redactor.redact(clean.pathname);
    if (clean.detail !== undefined) clean.detail = this.redactor.redact(clean.detail);
    await this.inner.write(clean);
  }
}
