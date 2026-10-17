import type { BrokerPolicy, CredentialGrant } from "./types.js";

/** Resolve a named group's grants to this registered agent on each request. */
export function effectiveGrant(policy: BrokerPolicy, agentId: string, credentialId: string): CredentialGrant | undefined {
  const direct = policy.agents.get(agentId)?.grants.get(credentialId);
  const inherited = policy.groupGrants.get(agentId)?.get(credentialId) ?? [];
  if (!direct && inherited.length === 0) return undefined;
  if (inherited.length === 0) return direct;
  return {
    credentialId,
    // Group operations precede direct operations. A group mutation that
    // requires approval cannot be bypassed by an overlapping direct rule.
    operations: [...inherited.flatMap((grant) => grant.operations), ...(direct?.operations ?? [])],
    deny: [...inherited.flatMap((grant) => grant.deny), ...(direct?.deny ?? [])],
  };
}

export function effectiveCredentialIds(policy: BrokerPolicy, agentId: string): string[] {
  const direct = policy.agents.get(agentId)?.grants.keys() ?? [];
  const inherited = policy.groupGrants.get(agentId)?.keys() ?? [];
  return [...new Set([...direct, ...inherited])];
}
