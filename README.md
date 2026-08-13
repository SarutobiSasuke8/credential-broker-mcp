# Credential Broker MCP

A local-first MCP server that lets AI agents use gated APIs **without ever
holding the keys**.

The agent asks the broker to make a request. The broker canonicalises the
URL, checks a declarative per-operation policy, verifies any required
approval at execution time, injects the secret at the last moment, calls
the upstream, redacts and filters the response, and writes a content-free
audit record. The secret lives with the broker process and is never
relayed to the agent in any representation the broker creates: raw,
Base64, base64url, percent-encoded, form-encoded, or Unicode-normalised.
An upstream that transforms a secret with a one-way function of its own
defeats string matching; scoped operations and metadata-only responses are
the defence there, and SECURITY.md states this boundary honestly.

> **Pre-release.** Nothing is published to npm yet. Treat `main` as a work
> in progress until a tagged `v0.1.0` exists.

## Why

Giving an agent an API key gives it everything the key can do, for as long
as the key lives, invisibly. Most agent tasks need a fraction of that:
*read these repos*, *query this endpoint*, *GET but never DELETE*. This
broker turns "here is my key" into "here is a scoped, observable
capability":

- **Possession vs use.** Agents exercise credentials; they never possess
  them.
- **Deny-by-default.** Authority is an enumerated list of named operations
  per credential. An absent grant is a denial, not an oversight. Deny
  rules always beat grants.
- **Nothing widens sideways.** A method, path, query parameter, body rule,
  or approval attached to one credential never widens any other
  credential.
- **One decision function.** The dry-run explainer and the live request
  path call the same `evaluate()`. What the broker reports and what it
  enforces cannot drift apart.
- **Content-free audit.** Who reached what, when, with what outcome, and
  through which lifecycle state. Never what they saw.

## Tools

| Tool | What it does |
|---|---|
| `broker_whoami` | Show the authenticated agent and its per-credential operation grants. |
| `broker_list_credentials` | Granted credentials: id, kind, base URL, provisioned or not. Never values. |
| `broker_explain_request` | Dry run: would this request be permitted, which rule decides it, and is an approval required or satisfied? No upstream call, no secret touched. |
| `broker_read` | GET or HEAD through a granted credential. Honestly annotated read-only. |
| `broker_mutate` | POST, PUT, PATCH, or DELETE. Annotated destructive and non-idempotent, because its strongest capability is. May require an approval and an idempotency key. |

## Policy (version 2)

One YAML file declares credentials and per-credential operation grants:

```yaml
version: 2
credentials:
  - id: github-readonly
    kind: bearer                 # bearer | header | basic | query
    env_var: GITHUB_READONLY_TOKEN
    base_url: https://api.github.com

agents:
  - id: researcher
    grants:
      - credential: github-readonly
        operations:
          - id: read-repo
            method: GET
            path: /repos/*/*     # literal segments, '*', or trailing '**'
            response_body: true  # default is metadata only
        deny:
          - /repos/*/*/keys
```

A request must clear every gate: identity provisioned and enabled,
credential granted, URL canonical and provably unambiguous, origin exactly
the credential's origin, path inside the credential's base path, no deny
match, and an operation whose method, path template, query parameter
allowlist, and body rule all match. `broker_explain_request` reports which
gate decided any outcome.

Semantics worth knowing:

- Operation paths are **relative to the credential's base path**. With
  `base_url: https://api.example.com/v2`, the template `/weather`
  authorises `/v2/weather`.
- Path matching is case-sensitive for operations and case-insensitive for
  deny rules, because many upstreams treat paths case-insensitively.
- Query parameters not named in `query_params` are denied.
- Operations without a `body` rule reject any request body. Body rules
  name allowed content types and a byte cap. Mutations must declare
  `requires_approval` explicitly, true or false.
- Responses default to metadata only. `response_body: true` relays the
  body, and only for content types in `response_content_types` (default
  `application/json`).
- Credentials of kind `query` must set `high_risk: true`: URLs are
  commonly retained by upstream and proxy telemetry, so a query-string
  secret has a wider blast radius than a header.

### Approvals

An operation with `requires_approval: true` executes only when the request
carries an `approval_id` that exists in the approval store, is bound to
exactly this principal, credential, and operation, is unexpired, and is
not revoked, checked at execution time, not config-load time. On stdio the
store is a JSON file (`config/approvals.json` by default) that is re-read
on every check, so editing it revokes access mid-flight:

```json
[
  {
    "id": "apr-2026-08-13-01",
    "agent_id": "researcher",
    "credential_id": "github-readonly",
    "operation_id": "create-issue",
    "expires_at": "2026-08-14T00:00:00Z",
    "revoked": false
  }
]
```

### Migrating from version 1

Version 1 policies shared one method list and path set across every
credential an agent held, so authority needed for one credential widened
all of them. The broker refuses v1 files. Convert with:

```bash
npm run migrate -- config/broker.yaml > config/broker-v2.yaml
```

The output is deliberately conservative (mutations require approval,
query parameters must be enumerated) and flagged for review: it makes the
old blast radius visible rather than silently preserving it.

## Safety properties

- Every URL is canonicalised once; policy and the outbound request consume
  the same canonical value, and the outbound bytes are round-trip checked.
  Encoded separators, double encoding, control characters, backslashes,
  userinfo, non-ASCII path segments, repeated or trailing slashes, and
  trailing-dot segments are rejected, not guessed at.
- Secrets are injected into exactly one header or query parameter. One
  redactor covers response bodies, relayed headers, error chains, and
  audit records, across raw, Base64, base64url, percent-encoded,
  form-encoded, and NFC/NFD representations, including truncation
  boundaries.
- Raw upstream error text is never relayed to agents; they receive a
  stable error category and a trace id, and the redacted detail goes to
  the audit log.
- Redirects are refused: a redirect could point anywhere, and `fetch`
  would re-send the injected credential there.
- A credential can only be exercised against its exact origin and base
  path; lookalike hosts and string-prefix tricks are refused.
- Plain-http upstreams are rejected at policy load, except on loopback.
- Response headers are allowlisted; `Set-Cookie` and friends are dropped.
- Responses are size-capped per operation, metadata-only by default.
- Mutations are a separate, honestly-annotated tool; approval state is
  checked at execution time; a dispatch failure on a mutation is recorded
  as `indeterminate`, never silently retried.
- Every decision is audited through its full lifecycle without request or
  response content, and audit records pass through the redactor too.

## Identity boundary

On stdio, `BROKER_AGENT_ID` is a **trusted-launcher assertion**: the
operator starting the process vouches for which agent is connected. It is
only a real boundary when the broker runs under the secure-launch profile
in [SECURITY.md](./SECURITY.md): dedicated OS identity, owner-only
policy/approvals/audit files, a fixed identity wrapper the agent cannot
edit, and no agent-readable secret environment. The broker loads only its
principal's secrets and scrubs every policy credential variable from its
environment after loading. One broker process serves one principal; never
share a process between agents.

## Running

```bash
npm install
cp config/broker.example.yaml config/broker.yaml   # then edit
BROKER_AGENT_ID=researcher npm start
```

Environment:

| Variable | Meaning |
|---|---|
| `BROKER_AGENT_ID` | Identity this stdio session runs as. Required. |
| `BROKER_POLICY_FILE` | Policy path. Default `config/broker.yaml`. |
| `BROKER_AUDIT_FILE` | Audit log path. Default `data/audit.jsonl`. |
| `BROKER_APPROVALS_FILE` | Approval store path. Default `config/approvals.json`. |
| *(per credential)* | Each credential's `env_var` carries its secret. |

Claude Code registration (once published; see the pre-release note above):

```json
{
  "mcpServers": {
    "credential-broker": {
      "command": "npx",
      "args": ["-y", "@sarutobi-sasuke/credential-broker-mcp"],
      "env": { "BROKER_AGENT_ID": "researcher" }
    }
  }
}
```

## What this is not

- Not an OAuth authorization server. It brokers static secrets you already
  hold. OAuth token acquisition and refresh are on the roadmap.
- Not a cloud service. It runs where your agents run, and your secrets
  stay on your machine. If you want hosted multi-tenant auth for agents,
  use a platform built for that.
- Not a bypass. It delegates *through* existing gates with scoped-down
  authority; it does not defeat anything.

## Roadmap

- [ ] OAuth 2.1 device and refresh flows for credentials that expire
- [ ] HTTP transport with mutually authenticated, audience-bound,
  expiring principal tokens through the same engine, matching
  [agent-handoff-mcp](https://github.com/SarutobiSasuke8/agent-handoff-mcp)
- [ ] Per-credential rate limits and spend counters
- [ ] Operator CLI: provision, rotate, revoke, approve

## Licence

Apache 2.0. See [LICENSE](./LICENSE).
