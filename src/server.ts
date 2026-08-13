import { McpServer } from "@modelcontextprotocol/server";
import { z } from "zod";

import { BrokerEngine } from "./engine.js";

import type { CallToolResult } from "@modelcontextprotocol/server";
import type { AuditSink } from "./audit.js";
import type { ApprovalStore, Clock, SecretProvider } from "./engine.js";
import type { BrokerPolicy } from "./types.js";

export interface BrokerServices {
  policy: BrokerPolicy;
  audit: AuditSink;
  secrets: SecretProvider;
  approvals?: ApprovalStore;
  clock?: Clock;
  fetchImpl?: typeof fetch;
}

function jsonResult(value: Record<string, unknown>): CallToolResult {
  return {
    content: [{ type: "text", text: JSON.stringify(value, null, 2) }],
    structuredContent: value,
  };
}

function errorResult(message: string): CallToolResult {
  return { isError: true, content: [{ type: "text", text: message }] };
}

const READ_METHOD_VALUES = ["GET", "HEAD"] as const;
const MUTATION_METHOD_VALUES = ["POST", "PUT", "PATCH", "DELETE"] as const;
const ALL_METHOD_VALUES = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"] as const;

/**
 * The published tool contract: which methods each tool accepts and how it is
 * annotated. Exported so contract tests can prove the annotations and the
 * accepted methods agree; a DELETE-capable tool must never advertise itself
 * as non-destructive.
 */
export const TOOL_CONTRACTS = {
  broker_whoami: {
    methods: [] as readonly string[],
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  },
  broker_list_credentials: {
    methods: [] as readonly string[],
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  },
  broker_explain_request: {
    methods: ALL_METHOD_VALUES as readonly string[],
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  },
  broker_read: {
    methods: READ_METHOD_VALUES as readonly string[],
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  broker_mutate: {
    methods: MUTATION_METHOD_VALUES as readonly string[],
    // Conservative by design: the strongest capability (DELETE) sets the
    // annotation for the whole tool. MCP annotations are hints, not an
    // authorization boundary, but they must never understate risk.
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
  },
} as const;

export function createBrokerMcpServer(services: BrokerServices, agentId: string): McpServer {
  const server = new McpServer({ name: "credential-broker-mcp", version: "0.1.0" });
  const { policy } = services;
  const engine = new BrokerEngine({
    policy,
    principalId: agentId,
    secrets: services.secrets,
    audit: services.audit,
    ...(services.approvals ? { approvals: services.approvals } : {}),
    ...(services.clock ? { clock: services.clock } : {}),
    ...(services.fetchImpl ? { fetchImpl: services.fetchImpl } : {}),
  });

  server.registerTool(
    "broker_whoami",
    {
      title: "Show broker identity",
      description: "Show the authenticated agent and its per-credential operation grants.",
      annotations: TOOL_CONTRACTS.broker_whoami.annotations,
    },
    async () => {
      const agent = policy.agents.get(agentId);
      if (!agent) return errorResult(`Identity '${agentId}' is not provisioned in the policy.`);
      return jsonResult({
        agent_id: agent.id,
        display_name: agent.displayName,
        enabled: agent.enabled,
        grants: [...agent.grants.values()].map((grant) => ({
          credential: grant.credentialId,
          deny: grant.deny.map((rule) => rule.path),
          operations: grant.operations.map((operation) => ({
            id: operation.id,
            method: operation.method,
            path: operation.path,
            query_params: operation.queryParams,
            accepts_body: Boolean(operation.body),
            response_body: operation.responseBody,
            requires_approval: operation.requiresApproval,
            requires_idempotency_key: operation.requiresIdempotencyKey,
            max_response_bytes: operation.maxResponseBytes,
          })),
        })),
      });
    },
  );

  server.registerTool(
    "broker_list_credentials",
    {
      title: "List granted credentials",
      description:
        "List the credentials this agent may exercise: id, kind, and base URL. Secret values are never exposed.",
      annotations: TOOL_CONTRACTS.broker_list_credentials.annotations,
    },
    async () => {
      const agent = policy.agents.get(agentId);
      if (!agent) return errorResult(`Identity '${agentId}' is not provisioned in the policy.`);
      const granted = [...agent.grants.keys()]
        .map((id) => policy.credentials.get(id))
        .filter((credential) => credential !== undefined)
        .map((credential) => ({
          id: credential.id,
          description: credential.description,
          kind: credential.kind,
          base_url: credential.baseUrl,
          high_risk: credential.highRisk,
          provisioned: services.secrets.getSecret(credential.id) !== undefined,
        }));
      return jsonResult({ credentials: granted });
    },
  );

  server.registerTool(
    "broker_explain_request",
    {
      title: "Explain a broker decision",
      description:
        "Dry run. Report whether a request would be permitted, which policy rule decides it, and " +
        "whether an approval is required or satisfied. Performs no upstream call and touches no secret.",
      inputSchema: z.object({
        credential: z.string().min(1).max(64),
        method: z.enum(ALL_METHOD_VALUES),
        url: z.string().min(1).max(4_000),
        approval_id: z.string().min(1).max(128).optional(),
      }),
      annotations: TOOL_CONTRACTS.broker_explain_request.annotations,
    },
    async ({ credential, method, url, approval_id }) => {
      const explained = await engine.explain({
        credentialId: credential,
        method,
        url,
        ...(approval_id !== undefined ? { approvalId: approval_id } : {}),
      });
      return jsonResult({
        allowed: explained.allowed,
        reason: explained.reason,
        deciding_rule: explained.decidingRule,
        ...(explained.operationId !== undefined ? { operation: explained.operationId } : {}),
        ...(explained.requiresApproval !== undefined ? { requires_approval: explained.requiresApproval } : {}),
        ...(explained.approvalState !== undefined ? { approval_state: explained.approvalState } : {}),
      });
    },
  );

  const runRequest = async (input: {
    credential: string;
    method: string;
    url: string;
    body?: string;
    contentType?: string;
    approvalId?: string;
    idempotencyKey?: string;
  }): Promise<CallToolResult> => {
    const result = await engine.execute({
      credentialId: input.credential,
      method: input.method,
      url: input.url,
      ...(input.body !== undefined ? { body: input.body } : {}),
      ...(input.contentType !== undefined ? { contentType: input.contentType } : {}),
      ...(input.approvalId !== undefined ? { approvalId: input.approvalId } : {}),
      ...(input.idempotencyKey !== undefined ? { idempotencyKey: input.idempotencyKey } : {}),
    });
    switch (result.kind) {
      case "denied":
        return errorResult(result.reason);
      case "error":
        return errorResult(result.message);
      case "success":
        return jsonResult({
          status: result.status,
          operation: result.operationId,
          headers: result.headers,
          truncated: result.truncated,
          trace_id: result.traceId,
          ...(result.body !== undefined ? { body: result.body } : {}),
          ...(result.bodyWithheldReason !== undefined ? { body_withheld: result.bodyWithheldReason } : {}),
        });
    }
  };

  server.registerTool(
    "broker_read",
    {
      title: "Make a brokered read request",
      description:
        "Make a GET or HEAD request through a granted credential. The broker injects the secret; " +
        "the agent never sees it. Responses are size-capped, header-filtered, and redacted. " +
        "Response bodies are relayed only when the matched operation grants response_body.",
      inputSchema: z.object({
        credential: z.string().min(1).max(64),
        method: z.enum(READ_METHOD_VALUES).default("GET"),
        url: z.string().min(1).max(4_000),
      }),
      annotations: TOOL_CONTRACTS.broker_read.annotations,
    },
    async ({ credential, method, url }) => runRequest({ credential, method, url }),
  );

  server.registerTool(
    "broker_mutate",
    {
      title: "Make a brokered state-changing request",
      description:
        "Make a POST, PUT, PATCH, or DELETE request through a granted credential. Treated as " +
        "destructive and non-idempotent: the matched operation may require an approval_id (checked " +
        "at execution time) and an idempotency_key. Upstream content is never assumed safe.",
      inputSchema: z.object({
        credential: z.string().min(1).max(64),
        method: z.enum(MUTATION_METHOD_VALUES),
        url: z.string().min(1).max(4_000),
        body: z.string().max(1_000_000).optional(),
        content_type: z.string().max(200).optional(),
        approval_id: z.string().min(1).max(128).optional(),
        idempotency_key: z.string().min(1).max(128).optional(),
      }),
      annotations: TOOL_CONTRACTS.broker_mutate.annotations,
    },
    async ({ credential, method, url, body, content_type, approval_id, idempotency_key }) =>
      runRequest({
        credential,
        method,
        url,
        ...(body !== undefined ? { body } : {}),
        ...(content_type !== undefined ? { contentType: content_type } : {}),
        ...(approval_id !== undefined ? { approvalId: approval_id } : {}),
        ...(idempotency_key !== undefined ? { idempotencyKey: idempotency_key } : {}),
      }),
  );

  return server;
}
