# Agent groups session, 2026-10-17

Source: `Workspace/Grok/Bots/Messages/inbox/codex/2026-10-17-0845-grok-agent-groups-feature-spec.md` in the Agentic Satellite Vault. The remote `feature/agent-groups` branch matched `main` at `d933f96` on intake; the brief's claimed committed spec was not present in that branch.

## Changes

- Added optional top-level `groups:` parsing in `src/policy.ts`, with registered-agent membership checks, duplicate and empty-group rejection, no nesting, and `all: ['*']` expansion.
- Added multiple selected agents to the key-manager add-API path. The page renders group shortcuts and individual checkboxes. The server writes one ordinary GET grant for each selected agent; it does not create a group authority in the runtime.
- Added per-credential group labels when all current members hold that credential, docs and example groups, plus unit and MCP contract coverage.

The existing broker decision function, deny rules, mutation approval checks, secret loading, audit path and stdio transport were not changed. Selecting a group does not itself grant any credential.

## Verification

- `npm run typecheck`: passed.
- `npm run lint`: passed.
- `npm test`: 114 passed.
- `npm run eval:contract`: 16 passed, including deny-beats-allow, cross-agent credential denial and mutation approval requirements with groups present in the synthetic policy.

No real credentials were read or used. No deployment, release or merge was attempted.
