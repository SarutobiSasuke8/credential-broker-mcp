export type CredentialKind = "bearer" | "header" | "basic" | "query";

export type HttpMethod = "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE";

export const READ_METHODS: readonly HttpMethod[] = ["GET", "HEAD"];
export const MUTATION_METHODS: readonly HttpMethod[] = ["POST", "PUT", "PATCH", "DELETE"];

export function isMutationMethod(method: string): boolean {
  return (MUTATION_METHODS as readonly string[]).includes(method.toUpperCase());
}

/**
 * A named upstream credential. The secret itself never appears in policy
 * files: `envVar` names the environment variable that holds it, and the
 * broker injects it into upstream requests at call time.
 */
export interface CredentialSpec {
  id: string;
  description: string;
  kind: CredentialKind;
  envVar: string;
  /** Header name for kind "header"; query parameter name for kind "query". */
  paramName?: string;
  /** Exact origin (scheme://host[:port]) requests must target. */
  origin: string;
  /** Decoded base-path segments under the origin. Empty when the base is the origin. */
  basePathSegments: string[];
  /** Display form of the configured base URL. */
  baseUrl: string;
  /**
   * Query-string credentials are commonly retained by upstream and proxy
   * telemetry. They must be explicitly acknowledged as high risk in policy.
   */
  highRisk: boolean;
}

/** Request-body rule for a mutation operation. Absent rule means no body is accepted. */
export interface BodyRule {
  contentTypes: string[];
  maxBytes: number;
}

/**
 * One named operation an agent may perform with one credential. This is the
 * unit of authority: nothing granted here widens any other credential.
 */
export interface OperationGrant {
  id: string;
  method: HttpMethod;
  /** Base-relative path template segments: literal, "*", or trailing "**". */
  pathTemplate: string[];
  /** Display form of the path template. */
  path: string;
  /** Allowlisted query parameter names. Any other parameter is a denial. */
  queryParams: string[];
  /** Body rule. Only mutations may carry one; absence rejects any body. */
  body?: BodyRule;
  /** Whether the response body is relayed at all. Default false: metadata only. */
  responseBody: boolean;
  /** Content types whose bodies may be relayed when responseBody is true. */
  responseContentTypes: string[];
  /** True: a valid, unexpired, unrevoked approval must exist at execution time. */
  requiresApproval: boolean;
  /** True: the caller must supply an idempotency key, recorded in audit. */
  requiresIdempotencyKey: boolean;
  /** Cap on response bytes returned for this operation. */
  maxResponseBytes: number;
}

/** Everything one agent may do with one credential. */
export interface CredentialGrant {
  credentialId: string;
  operations: OperationGrant[];
  /**
   * Belt-and-braces deny templates (base-relative), evaluated
   * case-insensitively against the canonical path. Deny beats any operation.
   */
  deny: { path: string; template: string[] }[];
}

/** What one agent identity may do through the broker. */
export interface AgentGrant {
  id: string;
  displayName: string;
  enabled: boolean;
  /** Per-credential grants, keyed by credential id. */
  grants: Map<string, CredentialGrant>;
}

export interface BrokerPolicy {
  version: 2;
  credentials: Map<string, CredentialSpec>;
  agents: Map<string, AgentGrant>;
}

export type RuleSource =
  | "agent-disabled"
  | "credential-not-granted"
  | "url-invalid"
  | "url-outside-base"
  | "grant-deny"
  | "method-not-allowed"
  | "no-operation"
  | "query-param-not-allowed"
  | "body-not-allowed"
  | "operation-allow";

export interface Decision {
  allowed: boolean;
  /** One sentence an operator can act on. */
  reason: string;
  /** The rule that produced the outcome, when a specific pattern decided it. */
  decidingRule: { source: RuleSource; pattern: string } | null;
}
