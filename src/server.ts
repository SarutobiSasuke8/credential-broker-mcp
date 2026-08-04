import { McpServer } from "@modelcontextprotocol/server";
import { z } from "zod";

import { evaluate, executeRequest } from "./gateway.js";

import type { CallToolResult } from "@modelcontextprotocol/server";
import type { AuditLogger } from "./audit.js";
import type { BrokerPolicy } from "./types.js";

export interface BrokerServices {
  policy: BrokerPolicy;
  audit: AuditLogger;
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

function safeHostAndPath(rawUrl: string): { host: string; pathname: string } {
  try {
    const url = new URL(rawUrl);
    return { host: url.host, pathname: url.pathname };
  } catch {
    return { host: "invalid", pathname: "invalid" };
  }
}

const requestShape = {
  credential: z.string().min(1).max(64),
  method: z.enum(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]),
  url: z.string().min(1).max(4_000),
};

export function createBrokerMcpServer(services: BrokerServices, agentId: string): McpServer {
  const server = new McpServer({ name: "credential-broker-mcp", version: "0.1.0" });
  const { policy, audit } = services;

  server.registerTool(
    "broker_whoami",
    {
      title: "Show broker identity",
      description: "Show the authenticated agent and its effective grants.",
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true },
    },
    async () => {
      const agent = policy.agents.get(agentId);
      if (!agent) return errorResult(`Identity '${agentId}' is not provisioned in the policy.`);
      return jsonResult({
        agent_id: agent.id,
        display_name: agent.displayName,
        enabled: agent.enabled,
        credentials: agent.credentials,
        methods: agent.methods,
        allow: agent.allow,
        deny: agent.deny,
        max_response_bytes: agent.maxResponseBytes,
      });
    },
  );

  server.registerTool(
    "broker_list_credentials",
    {
      title: "List granted credentials",
      description:
        "List the credentials this agent may exercise: id, kind, and base URL. Secret values are never exposed.",
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true },
    },
    async () => {
      const agent = policy.agents.get(agentId);
      if (!agent) return errorResult(`Identity '${agentId}' is not provisioned in the policy.`);
      const granted = agent.credentials
        .map((id) => policy.credentials.get(id))
        .filter((credential) => credential !== undefined)
        .map((credential) => ({
          id: credential.id,
          description: credential.description,
          kind: credential.kind,
          base_url: credential.baseUrl,
          provisioned: Boolean(process.env[credential.envVar]),
        }));
      return jsonResult({ credentials: granted });
    },
  );

  server.registerTool(
    "broker_explain_request",
    {
      title: "Explain a broker decision",
      description:
        "Dry run. Report whether a request would be permitted and which policy rule decides it. " +
        "Performs no upstream call.",
      inputSchema: z.object(requestShape),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true },
    },
    async ({ credential, method, url }) => {
      const decision = evaluate(policy, agentId, credential, method, url);
      return jsonResult({
        allowed: decision.allowed,
        reason: decision.reason,
        deciding_rule: decision.decidingRule,
      });
    },
  );

  server.registerTool(
    "broker_request",
    {
      title: "Make a brokered API request",
      description:
        "Make an HTTP request through a granted credential. The broker injects the secret; " +
        "the agent never sees it. Responses are size-capped and header-filtered.",
      inputSchema: z.object({
        ...requestShape,
        body: z.string().max(1_000_000).optional(),
        content_type: z.string().max(200).optional(),
      }),
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false },
    },
    async ({ credential, method, url, body, content_type }) => {
      const { host, pathname } = safeHostAndPath(url);
      const decision = evaluate(policy, agentId, credential, method, url);
      if (!decision.allowed || !decision.agent || !decision.credential) {
        await audit.write({
          agentId,
          credentialId: credential,
          method,
          host,
          pathname,
          outcome: "denied",
          detail: decision.reason,
        });
        return errorResult(decision.reason);
      }
      try {
        const response = await executeRequest(
          decision.credential,
          decision.agent,
          { method, url, ...(body !== undefined ? { body } : {}), ...(content_type ? { contentType: content_type } : {}) },
          services.fetchImpl ?? fetch,
        );
        await audit.write({
          agentId,
          credentialId: credential,
          method,
          host,
          pathname,
          outcome: "allowed",
          status: response.status,
        });
        return jsonResult({
          status: response.status,
          headers: response.headers,
          truncated: response.truncated,
          body: response.body,
        });
      } catch (error) {
        const message = error instanceof Error ? error.message : "Upstream request failed.";
        await audit.write({
          agentId,
          credentialId: credential,
          method,
          host,
          pathname,
          outcome: "error",
          detail: message,
        });
        return errorResult(message);
      }
    },
  );

  return server;
}
