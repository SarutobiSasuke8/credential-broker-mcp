# Approvals

An approval lets one agent run one state-changing operation on one
credential for a limited time. It never widens the policy; it only unlocks
an operation the policy already marks `requires_approval: true`.

## How the broker checks it

- The request must carry an `approval_id`.
- The approval must exist in the store, be bound to exactly this agent,
  credential and operation, be unexpired, and not be revoked.
- The check happens at execution time, not when the policy loads. On stdio
  the store is a JSON file (`config/approvals.json`, or
  `BROKER_APPROVALS_FILE`) re-read on every check, so editing it or
  revoking in the key manager stops access mid-flight.
- If the operation also sets `requires_idempotency_key`, the request must
  carry one and it is audited. The broker does not forward it upstream.

## The key manager's Approvals panel

- Lists every operation in the policy that requires an approval, per agent
  and credential.
- Creates an approval with a lifetime of 1 minute to 24 hours and shows the
  id for you to give the agent.
- Revokes active approvals. Expired ones are pruned after seven days.
- It cannot approve an operation the policy does not already mark as
  requiring approval, and it never grants write access itself. Write
  operations stay hand-written policy.

## What it trusts

- The policy file, for which operations exist and which need approval.
- Whoever can write the approvals file. That is the same trust as editing
  the policy.
- The operator handing the id to the right agent. An id is not a secret
  (an agent without the matching grant cannot use it), but keep it to the
  agent it was made for.

## Audit

An approved request is audited through `requested`, `approved`,
`executing` and its outcome, with the `approvalId` on the record. A request
without a valid approval is audited as `denied`.
