#!/usr/bin/env node
import { StdioServerTransport } from "@modelcontextprotocol/server/stdio";

import { AuditLogger } from "./audit.js";
import { loadBrokerPolicy } from "./policy.js";
import { createBrokerMcpServer } from "./server.js";

const agentId = process.env.BROKER_AGENT_ID;
if (!agentId) throw new Error("BROKER_AGENT_ID is required for stdio transport.");

const policyFile = process.env.BROKER_POLICY_FILE ?? "config/broker.yaml";
const auditFile = process.env.BROKER_AUDIT_FILE ?? "data/audit.jsonl";

const policy = await loadBrokerPolicy(policyFile);
if (!policy.agents.has(agentId)) {
  throw new Error(`Identity '${agentId}' is not provisioned in ${policyFile}.`);
}

const mcpServer = createBrokerMcpServer({ policy, audit: new AuditLogger(auditFile) }, agentId);
const transport = new StdioServerTransport(process.stdin, process.stdout);
await mcpServer.connect(transport);

process.on("SIGINT", () => void mcpServer.close());
process.on("SIGTERM", () => void mcpServer.close());
