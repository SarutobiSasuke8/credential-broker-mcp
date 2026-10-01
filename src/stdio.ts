#!/usr/bin/env node
import { StdioServerTransport } from "@modelcontextprotocol/server/stdio";

import { AuditLogger } from "./audit.js";
import { FileApprovalStore, loadPrincipalSecrets } from "./engine.js";
import { platformSecretStore } from "./keychain.js";
import { loadBrokerPolicy } from "./policy.js";
import { createBrokerMcpServer } from "./server.js";

/**
 * Stdio transport. The identity here is a trusted-launcher assertion: the
 * operator who sets BROKER_AGENT_ID vouches for the process on the other end
 * of the pipe. That is only a real boundary under the secure-launch profile
 * in SECURITY.md (dedicated OS identity, owner-only policy/audit/config, a
 * fixed identity wrapper, and no agent-readable secret environment). Without
 * it, any process that can set environment variables can pick an identity.
 */

const agentId = process.env.BROKER_AGENT_ID;
if (!agentId) throw new Error("BROKER_AGENT_ID is required for stdio transport.");

const policyFile = process.env.BROKER_POLICY_FILE ?? "config/broker.yaml";
const auditFile = process.env.BROKER_AUDIT_FILE ?? "data/audit.jsonl";
const approvalsFile = process.env.BROKER_APPROVALS_FILE ?? "config/approvals.json";

const policy = await loadBrokerPolicy(policyFile);
if (!policy.agents.has(agentId)) {
  throw new Error(`Identity '${agentId}' is not provisioned in ${policyFile}.`);
}

// Load only this principal's secrets, then scrub every credential variable
// from the process environment so child processes and later code cannot
// read them back. Credentials the environment leaves unset are read from the
// OS keychain, where the key manager (npm run keys) stores them.
const secrets = await loadPrincipalSecrets(policy, agentId, {
  scrubEnv: true,
  keychain: platformSecretStore(),
});

const mcpServer = createBrokerMcpServer(
  {
    policy,
    audit: new AuditLogger(auditFile),
    secrets,
    approvals: new FileApprovalStore(approvalsFile),
  },
  agentId,
);
const transport = new StdioServerTransport(process.stdin, process.stdout);
await mcpServer.connect(transport);

process.on("SIGINT", () => void mcpServer.close());
process.on("SIGTERM", () => void mcpServer.close());
