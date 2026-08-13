import { readFile } from "node:fs/promises";

import YAML from "yaml";
import { z } from "zod";

import { QUERY_KEY_PATTERN, canonicalizeRequestUrl, parsePathTemplate } from "./canonical.js";
import { isMutationMethod } from "./types.js";

import type {
  AgentGrant,
  BrokerPolicy,
  CredentialGrant,
  CredentialSpec,
  OperationGrant,
} from "./types.js";

const HTTP_METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"] as const;

const ID_PATTERN = /^[a-z0-9][a-z0-9._-]{1,63}$/u;
const CONTENT_TYPE_PATTERN = /^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/iu;

const rawCredentialSchema = z.object({
  id: z.string().regex(ID_PATTERN),
  description: z.string().default(""),
  kind: z.enum(["bearer", "header", "basic", "query"]),
  env_var: z.string().regex(/^[A-Z][A-Z0-9_]*$/u),
  param_name: z.string().min(1).max(100).optional(),
  base_url: z.string().url(),
  high_risk: z.boolean().default(false),
});

const rawBodySchema = z.object({
  content_types: z.array(z.string().regex(CONTENT_TYPE_PATTERN)).min(1),
  max_bytes: z.number().int().positive().max(1_000_000),
});

const rawOperationSchema = z.object({
  id: z.string().regex(ID_PATTERN),
  method: z.enum(HTTP_METHODS),
  path: z.string().min(1).max(500),
  query_params: z.array(z.string().regex(QUERY_KEY_PATTERN)).default([]),
  body: rawBodySchema.optional(),
  response_body: z.boolean().default(false),
  response_content_types: z.array(z.string().regex(CONTENT_TYPE_PATTERN)).min(1).default(["application/json"]),
  requires_approval: z.boolean().optional(),
  requires_idempotency_key: z.boolean().default(false),
  max_response_bytes: z.number().int().positive().max(10_000_000).optional(),
});

const rawGrantSchema = z.object({
  credential: z.string(),
  operations: z.array(rawOperationSchema).min(1),
  deny: z.array(z.string().min(1)).default([]),
});

const rawAgentSchema = z.object({
  id: z.string().regex(ID_PATTERN),
  display_name: z.string().default(""),
  enabled: z.boolean().default(true),
  grants: z.array(rawGrantSchema).min(1),
  max_response_bytes: z.number().int().positive().max(10_000_000).default(262_144),
});

const rawPolicySchema = z.object({
  version: z.number().int().positive(),
  credentials: z.array(rawCredentialSchema).min(1),
  agents: z.array(rawAgentSchema).min(1),
});

function isLoopbackHost(hostname: string): boolean {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "::1" || hostname === "[::1]";
}

interface NormalizedBase {
  origin: string;
  basePathSegments: string[];
  baseUrl: string;
}

function normalizeBaseUrl(raw: string, credentialId: string): NormalizedBase {
  const url = new URL(raw);
  // Plain http is a credential leak in transit. Loopback is exempt so local
  // services and tests can be brokered.
  if (url.protocol !== "https:" && !(url.protocol === "http:" && isLoopbackHost(url.hostname))) {
    throw new Error(`Credential '${credentialId}' must use https (or http on loopback only).`);
  }
  if (url.search || url.hash || url.username || url.password) {
    throw new Error(`Credential '${credentialId}' base_url must not carry query, fragment, or userinfo.`);
  }
  // The base URL itself must survive the same canonicalization as requests,
  // otherwise base-relative matching is undefined.
  const trimmed = url.href.endsWith("/") && url.pathname === "/" ? url.href.slice(0, -1) : url.href;
  const canonical = canonicalizeRequestUrl(trimmed);
  if (!canonical.ok) {
    throw new Error(`Credential '${credentialId}' base_url is not canonical: ${canonical.reason}`);
  }
  return {
    origin: canonical.request.origin,
    basePathSegments: [...canonical.request.pathSegments],
    baseUrl: `${canonical.request.origin}${canonical.request.canonicalPath === "/" ? "" : canonical.request.canonicalPath}`,
  };
}

function buildOperation(
  raw: z.infer<typeof rawOperationSchema>,
  agentId: string,
  credentialId: string,
  agentMaxResponseBytes: number,
): OperationGrant {
  const where = `agent '${agentId}', credential '${credentialId}', operation '${raw.id}'`;
  const mutation = isMutationMethod(raw.method);
  if (mutation && raw.requires_approval === undefined) {
    throw new Error(
      `${where}: mutations must state requires_approval explicitly (true or false). ` +
        `A state-changing grant is a conscious decision, not a default.`,
    );
  }
  if (!mutation && raw.body !== undefined) {
    throw new Error(`${where}: GET/HEAD operations must not declare a request body.`);
  }
  let pathTemplate: string[];
  try {
    pathTemplate = parsePathTemplate(raw.path);
  } catch (error) {
    throw new Error(`${where}: ${error instanceof Error ? error.message : String(error)}`);
  }
  return {
    id: raw.id,
    method: raw.method,
    pathTemplate,
    path: raw.path,
    queryParams: raw.query_params,
    ...(raw.body ? { body: { contentTypes: raw.body.content_types.map((t) => t.toLowerCase()), maxBytes: raw.body.max_bytes } } : {}),
    responseBody: raw.response_body,
    responseContentTypes: raw.response_content_types.map((t) => t.toLowerCase()),
    requiresApproval: raw.requires_approval ?? false,
    requiresIdempotencyKey: raw.requires_idempotency_key,
    maxResponseBytes: raw.max_response_bytes ?? agentMaxResponseBytes,
  };
}

export function parseBrokerPolicy(yamlText: string): BrokerPolicy {
  const yamlValue: unknown = YAML.parse(yamlText);
  // The version gate runs before full validation so a v1 policy gets
  // migration guidance instead of a wall of schema errors.
  const versionProbe = z.object({ version: z.number().int().positive() }).passthrough().parse(yamlValue);
  if (versionProbe.version === 1) {
    throw new Error(
      "Policy version 1 is no longer supported: its agent-wide method and path grants let authority " +
        "needed for one credential widen every other credential. Migrate to version 2 per-credential " +
        "operation grants. Run 'npm run migrate -- <policy-file>' for a reviewable conversion, and see " +
        "the Migration section of the README.",
    );
  }
  const parsed = rawPolicySchema.parse(yamlValue);

  if (parsed.version === 1) {
    throw new Error(
      "Policy version 1 is no longer supported: its agent-wide method and path grants let authority " +
        "needed for one credential widen every other credential. Migrate to version 2 per-credential " +
        "operation grants. Run 'npm run migrate -- <policy-file>' for a reviewable conversion, and see " +
        "the Migration section of the README.",
    );
  }
  if (parsed.version !== 2) {
    throw new Error(`Unknown policy version ${parsed.version}. This broker understands version 2.`);
  }

  const credentials = new Map<string, CredentialSpec>();
  for (const raw of parsed.credentials) {
    if (credentials.has(raw.id)) throw new Error(`Duplicate credential '${raw.id}'.`);
    if ((raw.kind === "header" || raw.kind === "query") && !raw.param_name) {
      throw new Error(`Credential '${raw.id}' of kind '${raw.kind}' requires param_name.`);
    }
    if (raw.kind === "query" && !raw.high_risk) {
      throw new Error(
        `Credential '${raw.id}' places its secret in the query string, which upstream and proxy ` +
          `telemetry commonly retain. Set high_risk: true to acknowledge this, or use a header credential.`,
      );
    }
    const base = normalizeBaseUrl(raw.base_url, raw.id);
    credentials.set(raw.id, {
      id: raw.id,
      description: raw.description,
      kind: raw.kind,
      envVar: raw.env_var,
      ...(raw.param_name ? { paramName: raw.param_name } : {}),
      origin: base.origin,
      basePathSegments: base.basePathSegments,
      baseUrl: base.baseUrl,
      highRisk: raw.high_risk,
    });
  }

  const agents = new Map<string, AgentGrant>();
  for (const raw of parsed.agents) {
    if (agents.has(raw.id)) throw new Error(`Duplicate agent '${raw.id}'.`);
    const grants = new Map<string, CredentialGrant>();
    for (const rawGrant of raw.grants) {
      if (!credentials.has(rawGrant.credential)) {
        throw new Error(`Agent '${raw.id}' references unknown credential '${rawGrant.credential}'.`);
      }
      if (grants.has(rawGrant.credential)) {
        throw new Error(`Agent '${raw.id}' declares credential '${rawGrant.credential}' twice.`);
      }
      const seenOperationIds = new Set<string>();
      const operations = rawGrant.operations.map((rawOperation) => {
        if (seenOperationIds.has(rawOperation.id)) {
          throw new Error(
            `Agent '${raw.id}', credential '${rawGrant.credential}': duplicate operation id '${rawOperation.id}'.`,
          );
        }
        seenOperationIds.add(rawOperation.id);
        return buildOperation(rawOperation, raw.id, rawGrant.credential, raw.max_response_bytes);
      });
      const deny = rawGrant.deny.map((path) => {
        try {
          return { path, template: parsePathTemplate(path) };
        } catch (error) {
          throw new Error(
            `Agent '${raw.id}', credential '${rawGrant.credential}', deny '${path}': ` +
              `${error instanceof Error ? error.message : String(error)}`,
          );
        }
      });
      grants.set(rawGrant.credential, { credentialId: rawGrant.credential, operations, deny });
    }
    agents.set(raw.id, {
      id: raw.id,
      displayName: raw.display_name,
      enabled: raw.enabled,
      grants,
    });
  }

  return { version: 2, credentials, agents };
}

export async function loadBrokerPolicy(filePath: string): Promise<BrokerPolicy> {
  return parseBrokerPolicy(await readFile(filePath, "utf8"));
}
