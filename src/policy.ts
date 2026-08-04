import { readFile } from "node:fs/promises";

import YAML from "yaml";
import { z } from "zod";

import type { AgentGrant, BrokerPolicy, CredentialSpec } from "./types.js";

const HTTP_METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"] as const;

const rawCredentialSchema = z.object({
  id: z.string().regex(/^[a-z0-9][a-z0-9._-]{1,63}$/u),
  description: z.string().default(""),
  kind: z.enum(["bearer", "header", "basic", "query"]),
  env_var: z.string().regex(/^[A-Z][A-Z0-9_]*$/u),
  param_name: z.string().min(1).max(100).optional(),
  base_url: z.string().url(),
});

const rawAgentSchema = z.object({
  id: z.string().regex(/^[a-z0-9][a-z0-9._-]{1,63}$/u),
  display_name: z.string().default(""),
  enabled: z.boolean().default(true),
  credentials: z.array(z.string()).min(1),
  methods: z.array(z.enum(HTTP_METHODS)).min(1),
  allow: z.array(z.string().min(1)).min(1),
  deny: z.array(z.string().min(1)).default([]),
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

function normalizeBaseUrl(raw: string, credentialId: string): string {
  const url = new URL(raw);
  // Plain http is a credential leak in transit. Loopback is exempt so local
  // services and tests can be brokered.
  if (url.protocol !== "https:" && !(url.protocol === "http:" && isLoopbackHost(url.hostname))) {
    throw new Error(`Credential '${credentialId}' must use https (or http on loopback only).`);
  }
  if (url.search || url.hash || url.username || url.password) {
    throw new Error(`Credential '${credentialId}' base_url must not carry query, fragment, or userinfo.`);
  }
  return url.href.endsWith("/") ? url.href.slice(0, -1) : url.href;
}

export function parseBrokerPolicy(yamlText: string): BrokerPolicy {
  const parsed = rawPolicySchema.parse(YAML.parse(yamlText));

  const credentials = new Map<string, CredentialSpec>();
  for (const raw of parsed.credentials) {
    if (credentials.has(raw.id)) throw new Error(`Duplicate credential '${raw.id}'.`);
    if ((raw.kind === "header" || raw.kind === "query") && !raw.param_name) {
      throw new Error(`Credential '${raw.id}' of kind '${raw.kind}' requires param_name.`);
    }
    credentials.set(raw.id, {
      id: raw.id,
      description: raw.description,
      kind: raw.kind,
      envVar: raw.env_var,
      ...(raw.param_name ? { paramName: raw.param_name } : {}),
      baseUrl: normalizeBaseUrl(raw.base_url, raw.id),
    });
  }

  const agents = new Map<string, AgentGrant>();
  for (const raw of parsed.agents) {
    if (agents.has(raw.id)) throw new Error(`Duplicate agent '${raw.id}'.`);
    for (const credentialId of raw.credentials) {
      if (!credentials.has(credentialId)) {
        throw new Error(`Agent '${raw.id}' references unknown credential '${credentialId}'.`);
      }
    }
    agents.set(raw.id, {
      id: raw.id,
      displayName: raw.display_name,
      enabled: raw.enabled,
      credentials: raw.credentials,
      methods: raw.methods.map((method) => method.toUpperCase()),
      allow: raw.allow,
      deny: raw.deny,
      maxResponseBytes: raw.max_response_bytes,
    });
  }

  return { version: parsed.version, credentials, agents };
}

export async function loadBrokerPolicy(filePath: string): Promise<BrokerPolicy> {
  return parseBrokerPolicy(await readFile(filePath, "utf8"));
}
