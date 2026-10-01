import YAML from "yaml";

import { parseBrokerPolicy } from "./policy.js";

import type { CredentialKind } from "./types.js";

/**
 * Policy edits made by the key manager. Every edit goes through the YAML
 * document model so operator comments survive, and the result must pass the
 * same parseBrokerPolicy() the broker uses before anything is written.
 *
 * The key manager only ever adds read access (GET, any path under the base
 * URL). Mutations stay a hand-written, reviewed policy decision.
 */

export interface NewCredentialInput {
  id: string;
  description: string;
  kind: CredentialKind;
  baseUrl: string;
  /** Header name for kind "header"; query parameter name for kind "query". */
  paramName?: string;
  /** Agent to grant read access, or null to add the credential with no grant. */
  grant: {
    agentId: string;
    /** Used only when the agent does not exist yet. */
    displayName?: string;
    queryParams: string[];
  } | null;
}

export const STARTER_POLICY_HEADER =
  "# Broker policy, created by the key manager (npm run keys).\n" +
  "# Secrets never appear here: each credential's key is read from env_var if\n" +
  "# set, otherwise from Windows Credential Manager. See README.md.\n";

/** Environment variable name derived from a credential id. */
export function envVarFor(credentialId: string): string {
  return `CB_${credentialId.toUpperCase().replace(/[^A-Z0-9]/gu, "_")}`;
}

function seqAt(doc: YAML.Document, key: string): YAML.YAMLSeq {
  const node = doc.get(key, true);
  if (YAML.isSeq(node)) return node;
  const seq = new YAML.YAMLSeq();
  doc.set(key, seq);
  return seq;
}

/**
 * Returns the new policy text. Throws with an operator-readable message when
 * the edit is invalid or would produce a policy the broker refuses.
 */
export function addCredentialToPolicy(existingText: string | null, input: NewCredentialInput): string {
  const doc = existingText === null
    ? YAML.parseDocument(`${STARTER_POLICY_HEADER}version: 2\n`)
    : YAML.parseDocument(existingText);
  if (doc.errors.length > 0) throw new Error(`Policy file is not valid YAML: ${doc.errors[0]?.message ?? "parse error"}`);

  const credentials = seqAt(doc, "credentials");
  const agents = seqAt(doc, "agents");

  const existingIds = credentials.items.map((item) => (YAML.isMap(item) ? item.get("id") : undefined));
  if (existingIds.includes(input.id)) throw new Error(`A credential named '${input.id}' already exists.`);

  const credential: Record<string, unknown> = {
    id: input.id,
    description: input.description,
    kind: input.kind,
    env_var: envVarFor(input.id),
  };
  if (input.kind === "header" || input.kind === "query") credential.param_name = input.paramName;
  credential.base_url = input.baseUrl;
  // The form makes the operator acknowledge this before it gets here.
  if (input.kind === "query") credential.high_risk = true;
  credentials.add(doc.createNode(credential));

  if (input.grant) {
    const grant = {
      credential: input.id,
      operations: [
        {
          id: "read",
          method: "GET",
          path: "/**",
          ...(input.grant.queryParams.length > 0 ? { query_params: input.grant.queryParams } : {}),
          response_body: true,
        },
      ],
    };
    const agent = agents.items.find((item) => YAML.isMap(item) && item.get("id") === input.grant?.agentId);
    if (YAML.isMap(agent)) {
      const grants = agent.get("grants", true);
      if (YAML.isSeq(grants)) grants.add(doc.createNode(grant));
      else agent.set("grants", doc.createNode([grant]));
    } else {
      agents.add(
        doc.createNode({
          id: input.grant.agentId,
          display_name: input.grant.displayName ?? input.grant.agentId,
          enabled: true,
          grants: [grant],
        }),
      );
    }
  }

  const text = doc.toString();
  try {
    parseBrokerPolicy(text);
  } catch (error) {
    throw new Error(describePolicyError(error));
  }
  return text;
}

/** Zod errors are JSON walls; turn them into one line. */
export function describePolicyError(error: unknown): string {
  if (error && typeof error === "object" && "issues" in error && Array.isArray(error.issues)) {
    const issue = error.issues[0] as { path?: unknown[]; message?: string } | undefined;
    if (issue) {
      const where = (issue.path ?? []).join(".");
      if (where === "agents" || where === "credentials") return `The policy needs at least one ${where.slice(0, -1)} with a grant.`;
      return `${where ? `${where}: ` : ""}${issue.message ?? "invalid value"}`;
    }
  }
  return error instanceof Error ? error.message : String(error);
}
