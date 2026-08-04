import { minimatch } from "minimatch";

import type { AgentGrant, BrokerPolicy, CredentialSpec, Decision } from "./types.js";

function firstMatch(pathname: string, patterns: string[]): string | null {
  return patterns.find((pattern) => minimatch(pathname, pattern, { dot: true, nocase: false })) ?? null;
}

function urlWithinBase(url: URL, baseUrl: string): boolean {
  const target = url.href;
  return target === baseUrl || target.startsWith(`${baseUrl}/`) || target.startsWith(`${baseUrl}?`);
}

/**
 * The single decision point. Both the live request path and the dry-run
 * explainer call this same function, so what the broker reports and what it
 * enforces cannot drift apart.
 *
 * Order: identity, grant, method, base URL, deny, allow. Deny beats allow,
 * and an absent allow is a denial, not an oversight.
 */
export function evaluate(
  policy: BrokerPolicy,
  agentId: string,
  credentialId: string,
  method: string,
  rawUrl: string,
): Decision & { agent?: AgentGrant; credential?: CredentialSpec; url?: URL } {
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
  if (!credential || !agent.credentials.includes(credentialId)) {
    return {
      allowed: false,
      reason: `Identity '${agentId}' holds no grant for credential '${credentialId}'.`,
      decidingRule: { source: "credential-not-granted", pattern: credentialId },
    };
  }

  const normalizedMethod = method.toUpperCase();
  if (!agent.methods.includes(normalizedMethod)) {
    return {
      allowed: false,
      reason: `Method ${normalizedMethod} is not granted to '${agentId}'. Granted: ${agent.methods.join(", ")}.`,
      decidingRule: { source: "method-not-allowed", pattern: normalizedMethod },
    };
  }

  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    return { allowed: false, reason: "The request URL is not a valid absolute URL.", decidingRule: null };
  }
  if (!urlWithinBase(url, credential.baseUrl)) {
    return {
      allowed: false,
      reason:
        `URL is outside credential '${credentialId}' base '${credential.baseUrl}'. ` +
        `A credential can only be exercised against its own API.`,
      decidingRule: { source: "url-outside-base", pattern: credential.baseUrl },
      credential,
    };
  }

  const denied = firstMatch(url.pathname, agent.deny);
  if (denied) {
    return {
      allowed: false,
      reason: `Denied by rule '${denied}'. Deny always beats a grant.`,
      decidingRule: { source: "agent-deny", pattern: denied },
      credential,
    };
  }

  const allowed = firstMatch(url.pathname, agent.allow);
  if (!allowed) {
    return {
      allowed: false,
      reason:
        `No allow rule for '${agentId}' covers path '${url.pathname}'. ` +
        `Access is deny-by-default, so an absent grant is a denial, not an oversight.`,
      decidingRule: null,
      credential,
    };
  }

  return {
    allowed: true,
    reason: `Allowed by rule '${allowed}' for ${normalizedMethod} within '${credential.baseUrl}'.`,
    decidingRule: { source: "agent-allow", pattern: allowed },
    agent,
    credential,
    url,
  };
}

/** Response headers that are safe to relay. Everything else is dropped. */
const SAFE_RESPONSE_HEADERS = ["content-type", "content-length", "retry-after", "x-ratelimit-remaining"];

export interface BrokeredResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
  truncated: boolean;
}

export interface RequestInput {
  method: string;
  url: string;
  body?: string;
  contentType?: string;
}

/**
 * Execute an approved request, injecting the secret at the last moment. The
 * secret comes from the environment, goes into exactly one header or query
 * parameter, and never appears in the response returned to the agent.
 */
export async function executeRequest(
  credential: CredentialSpec,
  agent: AgentGrant,
  input: RequestInput,
  fetchImpl: typeof fetch = fetch,
): Promise<BrokeredResponse> {
  const secret = process.env[credential.envVar];
  if (!secret) {
    throw new Error(`Credential '${credential.id}' is not provisioned (missing ${credential.envVar}).`);
  }

  const url = new URL(input.url);
  const headers = new Headers();
  headers.set("accept", "application/json, text/plain;q=0.9, */*;q=0.1");
  if (input.contentType) headers.set("content-type", input.contentType);

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

  const response = await fetchImpl(url, {
    method: input.method.toUpperCase(),
    headers,
    ...(input.body !== undefined ? { body: input.body } : {}),
    // A redirect can point anywhere, including outside the credential's base
    // URL, and fetch would re-send our injected header there. Refuse instead.
    redirect: "error",
    signal: AbortSignal.timeout(15_000),
  });

  const reader = response.body?.getReader();
  const chunks: Uint8Array[] = [];
  let received = 0;
  let truncated = false;
  if (reader) {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      received += value.byteLength;
      if (received > agent.maxResponseBytes) {
        truncated = true;
        chunks.push(value.subarray(0, value.byteLength - (received - agent.maxResponseBytes)));
        await reader.cancel();
        break;
      }
      chunks.push(value);
    }
  }

  const relayedHeaders: Record<string, string> = {};
  for (const name of SAFE_RESPONSE_HEADERS) {
    const value = response.headers.get(name);
    if (value !== null) relayedHeaders[name] = value;
  }

  let body = Buffer.concat(chunks).toString("utf8");
  // Defence in depth: if an upstream ever echoes the secret back (error pages
  // and debug endpoints do this), it must not reach the agent.
  if (body.includes(secret)) body = body.split(secret).join("[REDACTED]");

  return { status: response.status, headers: relayedHeaders, body, truncated };
}
