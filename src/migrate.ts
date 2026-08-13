import { readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";

import YAML from "yaml";
import { z } from "zod";

import { isMutationMethod } from "./types.js";

/**
 * Deterministic v1-to-v2 policy migration. v1 granted one shared method
 * list and path set per agent, so authority needed for one credential
 * widened every other credential. The conversion expands that union into
 * explicit per-credential operations, which makes the previous blast radius
 * visible: the output is a starting point the operator must review and
 * prune, not a drop-in equivalent.
 *
 * Conservative choices baked into the output:
 * - Every mutation operation gets requires_approval: true.
 * - query_params is empty (v1 never restricted queries; v2 denies
 *   unlisted parameters, so intended parameters must be enumerated).
 * - response_body: true preserves v1's behaviour of relaying bodies.
 * - Only simple segment globs ('*', trailing '**') are convertible. Other
 *   glob syntax fails the migration with an explanation.
 * - v1 matched patterns against the full URL path; v2 templates are
 *   relative to the credential's base path. Patterns are carried over
 *   verbatim and flagged for review when a base path exists.
 */

const v1CredentialSchema = z.object({
  id: z.string(),
  description: z.string().default(""),
  kind: z.enum(["bearer", "header", "basic", "query"]),
  env_var: z.string(),
  param_name: z.string().optional(),
  base_url: z.string(),
});

const v1AgentSchema = z.object({
  id: z.string(),
  display_name: z.string().default(""),
  enabled: z.boolean().default(true),
  credentials: z.array(z.string()).min(1),
  methods: z.array(z.enum(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"])).min(1),
  allow: z.array(z.string()).min(1),
  deny: z.array(z.string()).default([]),
  max_response_bytes: z.number().int().positive().default(262_144),
});

const v1PolicySchema = z.object({
  version: z.literal(1),
  credentials: z.array(v1CredentialSchema).min(1),
  agents: z.array(v1AgentSchema).min(1),
});

function assertConvertiblePattern(pattern: string, where: string): void {
  if (!pattern.startsWith("/")) {
    throw new Error(`${where}: pattern '${pattern}' does not start with '/'.`);
  }
  const segments = pattern === "/" ? [] : pattern.replace(/\/$/u, "").slice(1).split("/");
  segments.forEach((segment, index) => {
    if (segment === "*") return;
    if (segment === "**") {
      if (index !== segments.length - 1) {
        throw new Error(`${where}: '**' must be the final segment in '${pattern}'.`);
      }
      return;
    }
    if (/[*?[\]{}()!+@|]/u.test(segment)) {
      throw new Error(
        `${where}: pattern '${pattern}' uses glob syntax beyond segment '*' and trailing '**'. ` +
          `Rewrite it as explicit operations by hand.`,
      );
    }
  });
}

function slugForPattern(method: string, pattern: string, index: number): string {
  const cleaned = pattern
    .toLowerCase()
    .replace(/\*\*/gu, "any")
    .replace(/\*/gu, "one")
    .replace(/[^a-z0-9]+/gu, "-")
    .replace(/^-+|-+$/gu, "")
    .slice(0, 40);
  return `${method.toLowerCase()}-${cleaned || "root"}-${index}`;
}

export function migrateV1PolicyText(v1YamlText: string): string {
  const parsed = v1PolicySchema.parse(YAML.parse(v1YamlText));

  const credentials = parsed.credentials.map((credential) => ({
    ...credential,
    ...(credential.kind === "query" ? { high_risk: true } : {}),
  }));

  const agents = parsed.agents.map((agent) => ({
    id: agent.id,
    display_name: agent.display_name,
    enabled: agent.enabled,
    max_response_bytes: agent.max_response_bytes,
    grants: agent.credentials.map((credentialId) => {
      const operations = agent.methods.flatMap((method) =>
        agent.allow.map((pattern, index) => {
          assertConvertiblePattern(pattern, `agent '${agent.id}', allow`);
          const normalized = pattern === "/" ? "/" : pattern.replace(/\/$/u, "");
          const mutation = isMutationMethod(method);
          return {
            id: slugForPattern(method, normalized, index),
            method,
            path: normalized,
            query_params: [],
            response_body: true,
            ...(mutation ? { requires_approval: true } : {}),
          };
        }),
      );
      const deny = agent.deny.map((pattern) => {
        assertConvertiblePattern(pattern, `agent '${agent.id}', deny`);
        return pattern === "/" ? "/" : pattern.replace(/\/$/u, "");
      });
      return { credential: credentialId, operations, ...(deny.length > 0 ? { deny } : {}) };
    }),
  }));

  const header = [
    "# Migrated from policy version 1 by 'npm run migrate'. REVIEW BEFORE USE.",
    "# v1 shared one method/path grant across every credential; this expansion",
    "# makes that blast radius explicit. Prune operations each credential does",
    "# not need, enumerate query_params (v2 denies unlisted parameters), and",
    "# check paths: v2 templates are relative to each credential's base path,",
    "# while v1 matched the full URL path.",
    "# Mutations were given requires_approval: true; relax deliberately if safe.",
    "",
  ].join("\n");

  return header + YAML.stringify({ version: 2, credentials, agents });
}

async function main(): Promise<void> {
  const file = process.argv[2];
  if (!file) {
    console.error("Usage: npm run migrate -- <v1-policy-file>");
    process.exitCode = 2;
    return;
  }
  const text = await readFile(file, "utf8");
  process.stdout.write(migrateV1PolicyText(text));
}

const invokedDirectly =
  typeof process.argv[1] === "string" && import.meta.url === pathToFileURL(process.argv[1]).href;
if (invokedDirectly) {
  await main();
}
