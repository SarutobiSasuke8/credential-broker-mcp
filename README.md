# Credential Broker MCP

A local-first MCP server that lets AI agents use gated APIs **without ever
holding the keys**.

The agent asks the broker to make a request. The broker checks a declarative
policy, injects the secret at the last moment, calls the upstream, filters the
response, and writes a content-free audit record. The secret lives in an
environment variable on the operator's machine and is never visible to the
agent, in any tool result, under any outcome.

## Why

Giving an agent an API key gives it everything the key can do, for as long as
the key lives, invisibly. Most agent tasks need a fraction of that: *read
these repos*, *query this endpoint*, *GET but never DELETE*. This broker turns
"here is my key" into "here is a scoped, observable capability":

- **Possession vs use.** Agents exercise credentials; they never possess them.
- **Deny-by-default.** An absent grant is a denial, not an oversight. Deny
  rules always beat allow rules.
- **One decision function.** The dry-run explainer and the live request path
  call the same `evaluate()`. What the broker reports and what it enforces
  cannot drift apart.
- **Content-free audit.** Who reached what, when, with what outcome. Never
  what they saw.

## Tools

| Tool | What it does |
|---|---|
| `broker_whoami` | Show the authenticated agent and its effective grants. |
| `broker_list_credentials` | Granted credentials: id, kind, base URL, provisioned or not. Never values. |
| `broker_explain_request` | Dry run: would this request be permitted, and which rule decides it? |
| `broker_request` | Make the request. Secret injected server-side, response capped and filtered. |

## Policy

One YAML file declares credentials and grants:

```yaml
version: 1
credentials:
  - id: github-readonly
    kind: bearer                 # bearer | header | basic | query
    env_var: GITHUB_READONLY_TOKEN
    base_url: https://api.github.com

agents:
  - id: researcher
    credentials: [github-readonly]
    methods: [GET]
    allow: ["/repos/**"]
    deny: ["/repos/*/*/keys"]
    max_response_bytes: 262144
```

A request must clear every gate: identity provisioned and enabled, credential
granted, method granted, URL inside the credential's base URL, no deny match,
and an explicit allow match. `broker_explain_request` reports which gate
decided any outcome.

## Safety properties

- Secrets are injected into exactly one header or query parameter and are
  redacted from response bodies if an upstream ever echoes them back.
- Redirects are refused: a redirect could point anywhere, and `fetch` would
  re-send the injected credential there.
- A credential can only be exercised against its own `base_url`; lookalike
  hosts sharing the base as a string prefix are refused.
- Plain-http upstreams are rejected at policy load, except on loopback.
- Response headers are allowlisted; `Set-Cookie` and friends are dropped.
- Responses are size-capped per agent.
- Every decision is audited without request or response content.

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
| *(per credential)* | Each credential's `env_var` carries its secret. |

Claude Code registration:

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
- Not a cloud service. It runs where your agents run, and your secrets stay
  on your machine. If you want hosted multi-tenant auth for agents, use a
  platform built for that.
- Not a bypass. It delegates *through* existing gates with scoped-down
  authority; it does not defeat anything.

## Roadmap

- [ ] OAuth 2.1 device and refresh flows for credentials that expire
- [ ] HTTP transport with per-agent bearer tokens, matching
  [agent-handoff-mcp](https://github.com/SarutobiSasuke8/agent-handoff-mcp)
- [ ] Per-credential rate limits and spend counters
- [ ] Operator CLI: provision, rotate, revoke

## Licence

Apache 2.0. See [LICENSE](./LICENSE).
