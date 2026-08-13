import { canonicalizeRequestUrl, matchPathTemplate } from "./canonical.js";

import type { CanonicalRequest } from "./canonical.js";
import type {
  AgentGrant,
  BrokerPolicy,
  CredentialGrant,
  CredentialSpec,
  Decision,
  OperationGrant,
} from "./types.js";

/** The request as evaluated: method plus optional body metadata. */
export interface EvaluationInput {
  method: string;
  url: string;
  /** Raw body string when present; undefined means no body is sent. */
  body?: string;
  contentType?: string;
}

export interface EvaluationOutcome extends Decision {
  agent?: AgentGrant;
  credential?: CredentialSpec;
  grant?: CredentialGrant;
  operation?: OperationGrant;
  canonical?: CanonicalRequest;
}

/**
 * The single decision point. The live request path and the dry-run explainer
 * call this same function, so what the broker reports and what it enforces
 * cannot drift apart.
 *
 * Order: identity, grant, canonical URL, base, deny, operation (method,
 * path, query, body). Deny beats any operation, and an absent operation is a
 * denial, not an oversight. Deny templates are matched case-insensitively;
 * operation templates case-sensitively.
 */
export function evaluate(
  policy: BrokerPolicy,
  agentId: string,
  credentialId: string,
  input: EvaluationInput,
): EvaluationOutcome {
  const agent = policy.agents.get(agentId);
  if (!agent) {
    return { allowed: false, reason: `Identity '${agentId}' is not provisioned in the policy.`, decidingRule: null };
  }
  if (!agent.enabled) {
    return {
      allowed: false,
      reason: `Identity '${agentId}' is disabled.`,
      decidingRule: { source: "agent-disabled", pattern: agentId },
    };
  }

  const credential = policy.credentials.get(credentialId);
  const grant = agent.grants.get(credentialId);
  if (!credential || !grant) {
    return {
      allowed: false,
      reason: `Identity '${agentId}' holds no grant for credential '${credentialId}'.`,
      decidingRule: { source: "credential-not-granted", pattern: credentialId },
    };
  }

  const canonical = canonicalizeRequestUrl(input.url);
  if (!canonical.ok) {
    return {
      allowed: false,
      reason: `${canonical.reason} The broker only forwards URLs whose upstream meaning it can prove.`,
      decidingRule: { source: "url-invalid", pattern: "canonical-url" },
      agent,
      credential,
      grant,
    };
  }
  const request = canonical.request;

  const base = credential.basePathSegments;
  const withinBase =
    request.origin === credential.origin &&
    request.pathSegments.length >= base.length &&
    base.every((segment, index) => request.pathSegments[index] === segment);
  if (!withinBase) {
    return {
      allowed: false,
      reason:
        `URL is outside credential '${credentialId}' base '${credential.baseUrl}'. ` +
        `A credential can only be exercised against its own API.`,
      decidingRule: { source: "url-outside-base", pattern: credential.baseUrl },
      agent,
      credential,
      grant,
      canonical: request,
    };
  }
  const relativeSegments = request.pathSegments.slice(base.length);

  for (const deny of grant.deny) {
    if (matchPathTemplate(deny.template, relativeSegments, { caseInsensitive: true })) {
      return {
        allowed: false,
        reason: `Denied by rule '${deny.path}'. Deny always beats a grant.`,
        decidingRule: { source: "grant-deny", pattern: deny.path },
        agent,
        credential,
        grant,
        canonical: request,
      };
    }
  }

  const normalizedMethod = input.method.toUpperCase();
  const methodOperations = grant.operations.filter((operation) => operation.method === normalizedMethod);
  if (methodOperations.length === 0) {
    const granted = [...new Set(grant.operations.map((operation) => operation.method))].join(", ");
    return {
      allowed: false,
      reason:
        `No operation grants ${normalizedMethod} on credential '${credentialId}' for '${agentId}'. ` +
        `Granted methods here: ${granted}.`,
      decidingRule: { source: "method-not-allowed", pattern: normalizedMethod },
      agent,
      credential,
      grant,
      canonical: request,
    };
  }

  let queryFailure: { operation: OperationGrant; param: string } | null = null;
  for (const operation of methodOperations) {
    if (!matchPathTemplate(operation.pathTemplate, relativeSegments)) continue;
    const offending = request.query.find(([key]) => !operation.queryParams.includes(key));
    if (offending) {
      queryFailure = { operation, param: offending[0] };
      continue;
    }
    // Body rules.
    if (input.body !== undefined) {
      if (!operation.body) {
        return {
          allowed: false,
          reason:
            `Operation '${operation.id}' does not accept a request body. ` +
            `Operations without an explicit body rule reject all bodies.`,
          decidingRule: { source: "body-not-allowed", pattern: operation.id },
          agent,
          credential,
          grant,
          canonical: request,
        };
      }
      const contentType = (input.contentType ?? "").toLowerCase().split(";")[0]?.trim() ?? "";
      if (!operation.body.contentTypes.includes(contentType)) {
        return {
          allowed: false,
          reason:
            `Operation '${operation.id}' accepts body content types ${operation.body.contentTypes.join(", ")}; ` +
            `got '${contentType || "none"}'.`,
          decidingRule: { source: "body-not-allowed", pattern: operation.id },
          agent,
          credential,
          grant,
          canonical: request,
        };
      }
      if (Buffer.byteLength(input.body, "utf8") > operation.body.maxBytes) {
        return {
          allowed: false,
          reason: `Request body exceeds operation '${operation.id}' limit of ${operation.body.maxBytes} bytes.`,
          decidingRule: { source: "body-not-allowed", pattern: operation.id },
          agent,
          credential,
          grant,
          canonical: request,
        };
      }
    }
    return {
      allowed: true,
      reason:
        `Allowed by operation '${operation.id}' (${operation.method} ${operation.path}) ` +
        `within '${credential.baseUrl}'.`,
      decidingRule: { source: "operation-allow", pattern: operation.id },
      agent,
      credential,
      grant,
      operation,
      canonical: request,
    };
  }

  if (queryFailure) {
    return {
      allowed: false,
      reason:
        `Query parameter '${queryFailure.param}' is not allowlisted for operation '${queryFailure.operation.id}'. ` +
        `Allowed: ${queryFailure.operation.queryParams.join(", ") || "(none)"}.`,
      decidingRule: { source: "query-param-not-allowed", pattern: queryFailure.param },
      agent,
      credential,
      grant,
      canonical: request,
    };
  }

  return {
    allowed: false,
    reason:
      `No operation for '${agentId}' on credential '${credentialId}' covers ${normalizedMethod} ` +
      `'${request.canonicalPath}'. Access is deny-by-default, so an absent grant is a denial, not an oversight.`,
    decidingRule: { source: "no-operation", pattern: request.canonicalPath },
    agent,
    credential,
    grant,
    canonical: request,
  };
}
