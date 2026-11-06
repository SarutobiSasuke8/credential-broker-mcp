#!/usr/bin/env node
import { StdioServerTransport } from "@modelcontextprotocol/server/stdio";

import { AuditLogger } from "./audit.js";
import { FileApprovalStore, loadPrincipalSecrets } from "./engine.js";
import { FilePauseGuard, pauseFilePath } from "./kill-switch.js";
import { KeyRequester, spawnKeyManagerLauncher } from "./key-request.js";
import { platformSecretStore } from "./keychain.js";
import { loadBrokerPolicy } from "./policy.js";
import { ReloadWatcher, reloadMarkerPath } from "./reload.js";
import { createBrokerMcpServer } from "./server.js";

import type { AuditRecord } from "./audit.js";
import type { SecretProvider } from "./engine.js";
import type { BrokerPolicy } from "./types.js";

function reloadRecord(agent: string, detail: string): AuditRecord {
  return {
    traceId: `reload-${Date.now().toString(36)}`,
    agentId: agent,
    credentialId: "-",
    method: "RELOAD",
    host: "broker.local",
    pathname: "/",
    outcome: "requested",
    detail,
  };
}

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
// Keep the credential variables the environment supplied, so a hot reload can
// rebuild the same secrets after the scrub below has removed them from
// process.env. The values stay in this process only.
const envSnapshot: Record<string, string | undefined> = {};
for (const credential of policy.credentials.values()) envSnapshot[credential.envVar] = process.env[credential.envVar];

const keychain = platformSecretStore();
const secrets = await loadPrincipalSecrets(policy, agentId, { scrubEnv: true, keychain });
const audit = new AuditLogger(auditFile);

// Opt-in hot reload: pick up key manager changes without restarting the MCP
// client. A failed reload keeps the previous working state.
let refresh: (() => Promise<{ policy: BrokerPolicy; secrets: SecretProvider } | null>) | undefined;
if (process.env.BROKER_HOT_RELOAD === "1") {
  const watcher = new ReloadWatcher<{ policy: BrokerPolicy; secrets: SecretProvider }>({
    markerFile: reloadMarkerPath(policyFile),
    async load() {
      const nextPolicy = await loadBrokerPolicy(policyFile);
      if (!nextPolicy.agents.has(agentId)) throw new Error(`Identity '${agentId}' is no longer in the policy; keeping the previous one.`);
      const env: Record<string, string | undefined> = { ...envSnapshot };
      for (const credential of nextPolicy.credentials.values()) env[credential.envVar] ??= process.env[credential.envVar];
      return { policy: nextPolicy, secrets: await loadPrincipalSecrets(nextPolicy, agentId, { env, scrubEnv: false, keychain }) };
    },
    onReload: () => audit.write(reloadRecord(agentId, "policy and keys reloaded")),
    onFailure: (message) => audit.write(reloadRecord(agentId, `reload failed, previous state kept: ${message.slice(0, 160)}`)),
  });
  await watcher.init();
  refresh = () => watcher.refresh();
}

const mcpServer = createBrokerMcpServer(
  {
    policy,
    audit,
    secrets,
    approvals: new FileApprovalStore(approvalsFile),
    // Always on: a missing pause file means nothing is paused.
    pause: new FilePauseGuard(pauseFilePath(policyFile)),
    ...(refresh ? { refresh } : {}),
    // Opt-in per process: lets this agent ask the operator for a key by
    // opening the key manager. Off unless the operator sets the variable.
    ...(process.env.BROKER_ALLOW_KEY_REQUESTS === "1" ? { keyRequests: new KeyRequester({ launcher: spawnKeyManagerLauncher() }) } : {}),
  },
  agentId,
);
const transport = new StdioServerTransport(process.stdin, process.stdout);
await mcpServer.connect(transport);

process.on("SIGINT", () => void mcpServer.close());
process.on("SIGTERM", () => void mcpServer.close());
