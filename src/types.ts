export type CredentialKind = "bearer" | "header" | "basic" | "query";

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
  /** Requests through this credential must start with this URL. */
  baseUrl: string;
}

/** What one agent identity may do through the broker. */
export interface AgentGrant {
  id: string;
  displayName: string;
  enabled: boolean;
  /** Credential ids this agent may exercise. */
  credentials: string[];
  /** Uppercase HTTP methods this agent may use. */
  methods: string[];
  /** Path globs (matched against the URL pathname) the agent may reach. */
  allow: string[];
  /** Path globs denied to this agent. Deny always beats allow. */
  deny: string[];
  /** Cap on response bytes returned to this agent. */
  maxResponseBytes: number;
}

export interface BrokerPolicy {
  version: number;
  credentials: Map<string, CredentialSpec>;
  agents: Map<string, AgentGrant>;
}

export type RuleSource =
  | "agent-disabled"
  | "credential-not-granted"
  | "method-not-allowed"
  | "url-outside-base"
  | "agent-deny"
  | "agent-allow";

export interface Decision {
  allowed: boolean;
  /** One sentence an operator can act on. */
  reason: string;
  /** The rule that produced the outcome, when a specific pattern decided it. */
  decidingRule: { source: RuleSource; pattern: string } | null;
}
