import { appendFile, mkdir } from "node:fs/promises";
import path from "node:path";

/**
 * Content-free audit record. The path is recorded; the query string, request
 * body, and response body are deliberately not, since they may carry secrets
 * or personal data. The audit answers "who reached what, when, with what
 * outcome", never "what did they see".
 */
export interface AuditRecord {
  agentId: string;
  credentialId: string;
  method: string;
  host: string;
  pathname: string;
  outcome: "allowed" | "denied" | "error";
  status?: number;
  detail?: string;
}

export class AuditLogger {
  public constructor(private readonly file: string) {}

  public async write(record: AuditRecord): Promise<void> {
    await mkdir(path.dirname(this.file), { recursive: true });
    await appendFile(this.file, `${JSON.stringify({ at: new Date().toISOString(), ...record })}\n`, "utf8");
  }
}

/** Drops records; used when auditing is disabled or in tests. */
export class NullAuditLogger extends AuditLogger {
  public constructor() {
    super("");
  }

  public override async write(): Promise<void> {
    // intentionally empty
  }
}
