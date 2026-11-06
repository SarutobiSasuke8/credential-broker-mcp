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

## Five-minute quickstart

Needs Node 22 or 24. Keys are stored in the OS keychain: Windows Credential
Manager, the macOS login keychain, or the Secret Service on Linux
(GNOME Keyring or KWallet through `secret-tool`). Without one, set each
credential's `env_var` instead.

1. **Pick a folder for your policy** and open the key manager. It prints a
   link and opens it in your browser.

   ```bash
   npx -p @sarutobi-sasuke/credential-broker-mcp credential-broker-keys
   ```

   Set `BROKER_POLICY_FILE` first if you want the policy somewhere other
   than the package folder, for example `%USERPROFILE%\credential-broker\broker.yaml`.
   From a clone of this repo, run `npm ci && npm run build` once, then
   `npm run keys`.

2. **Add one key.** In *Add a key*: short name `github`, base URL
   `https://api.github.com`, paste a token, tick the agent that may use it
   (or add a new one called `claude`), press **Add key**. The key goes into
   Credential Manager and the policy file gets a read-only grant. Press
   **Test** on the card to prove the key works.

3. **Register with Claude Code.** Open *Connect to Claude Code* at the
   bottom of the page, pick the agent, copy the `claude mcp add` command and
   run it. Nothing secret is in that command.

4. **Make a granted call and a denied call.** In Claude Code:

   > Use `broker_explain_request` for a GET to
   > `https://api.github.com/repos/octocat/hello-world` with credential `github`.

   It answers *allowed* and names the deciding rule. Now ask the same with
   `DELETE`: *denied*, no grant. Then ask for `broker_read` on the GET and
   you get the response body with the token redacted wherever it might
   appear. The audit log (`data/audit.jsonl`) now holds the who, what and
   outcome, never the content.

5. **Pause and resume.** Press **Pause all access** in the page header and
   type `PAUSE`. The agent's next call is refused with a message not to
   retry. Press **Resume all access** and type `RESUME`. From a terminal:
   `npm run pause -- on` and `npm run pause -- off`.

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
| `broker_request_credential` | Opt-in (`BROKER_ALLOW_KEY_REQUESTS=1`). Asks the operator for a key by opening the key manager pre-filled. The agent never sees the page, the token or the key. |

## Policy (version 2)

Policy objects reject unknown fields at every level. Correct misspelt keys
and remove unsupported metadata before upgrading; ignored fields could
otherwise remove a restriction, such as a misspelt `enabled` or `deny`.

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

## Managing keys

```bash
npm install
npm run keys
```

This opens a local page in your browser where you:

- **Add an API**: name, base URL, how the key is sent, paste the key, then
  choose individual agents or group shortcuts. The key goes into the OS
  keychain; the policy file gets persistent group assignments and
  separate read-only grants for individually selected agents (GET on any path under the
  base URL, only the query parameters you list).
- **Save, replace, test, or remove a key** for any API already in the
  policy. Test makes one GET with the key and reports the status code
  only. Keys are write-only: the page never shows one back.
- **Import keys you already have.** "Find my keys" looks in Windows user
  environment variables, MCP client configs (Claude Code, Claude Desktop,
  Cursor), and `.env` files under `Documents` and `C:\Dev` (override with
  `BROKER_IMPORT_ROOTS`, semicolon-separated). Known providers (OpenRouter,
  Gemini, ElevenLabs, DigitalOcean, Nansen, TypeSafe, Clerk, CoinGecko,
  PixelLab, OpenAI, Anthropic, GitHub) can be added as APIs in one click
  and are tested straight away; anything else is stored only. Values are
  read by the key manager process and never sent to the page. Wallet keys
  are flagged and never offered as APIs. Original copies are not touched.
- **Copy the `claude mcp add` command** that registers the broker for an
  agent with absolute paths filled in.

Write access (POST, PUT, PATCH, DELETE) is never granted from the page;
add those operations to the policy by hand. Restart the MCP client (or set `BROKER_HOT_RELOAD=1`, see below) after
changing a key, because the broker loads keys once at start-up.

Optional top-level `groups:` in `broker.yaml` maps a name to registered agent
IDs. `all: ['*']` means every registered agent. The example policy shows
`hermes`, `grokbot` and `all`; replace their sample members with your own IDs.
Groups cannot be empty, nested or refer to unknown agents. Selecting a group
in the key manager writes a `group_grants:` entry for that credential. The
broker resolves it for the authenticated agent on every request. Editing
`groups:` changes access after the broker restarts and reloads its policy.
Membership alone grants nothing; a matching `group_grants:` entry is required.
Group and direct denials are combined, and group mutations must require
approval. The key cards show groups actually assigned to each credential.

Keys live in the OS keychain as `credential-broker/<credential-id>`: on
Windows in Control Panel > Credential Manager > Windows Credentials, on
macOS in the login keychain (Keychain Access shows them under that
service name), on Linux in the Secret Service (Seahorse or KWallet
Manager shows them with the `credential-broker` attribute). The macOS and
Linux backends drive the `security` and `secret-tool` commands and send
the key over stdin, never on a command line; they are unit tested against
a fake and still need a real round trip on each platform before you rely
on them. An `env_var` value, if set, overrides
the stored key. The page listens on 127.0.0.1 only, needs a per-run token
from the printed link, and closes after 30 minutes idle. On other
platforms, set each credential's `env_var` instead.

### Expiry dates and notes

Each key can carry an expiry date and a free-text note (where it was created,
how to rotate it). They are kept in `key-notes.json` beside the policy file
(override with `BROKER_KEY_NOTES_FILE`), never in the policy and never with the
secret. Keys that are expired or expire within 30 days raise a banner, sort
first, and show a badge on their card. Nothing in the broker engine reads this
file, so a date never blocks a request; it is a reminder for you.

### Letting an agent ask for a key

Set `BROKER_ALLOW_KEY_REQUESTS=1` on a broker process to give that agent the
`broker_request_credential` tool. The agent supplies a lowercase name, a short
reason and, optionally, a known provider id (for example `github`, `openai`,
`itch`). The broker then opens the key manager in your browser, pre-filled with
the name and the reason, with a banner saying which agent asked.

- The agent never receives the page address, the session token or anything you
  type. The tool result says only that a window opened.
- The base URL and key style come from the broker's own table of known
  providers, never from the agent. An unknown provider leaves them blank for you
  to fill in, so an agent cannot steer a key to a host of its choosing.
- Nothing is added until you press the button, and you choose who may use it.
- Requests are limited to one per credential per 10 minutes and five an hour per
  process, and each one writes a content-free audit line.
- The broker loads keys when it starts, so restart the MCP client after saving.
  The tool is off by default.

### Panic button

The header of the key manager has a red **Pause all access** button. It opens a
dialog that says what will happen, shows how many agents and keys are affected,
and asks you to type `PAUSE`. From then on every broker refuses every request on
its next call. Nothing is deleted: policy, keys and approvals stay as they were.
**Resume all access** asks you to type `RESUME`, because resuming is the risky
direction. Pausing one agent (Agents panel) or one key (its card) asks a plain
confirmation and then offers an eight second **Undo**; resuming one asks a
confirmation.

The typed word is a safeguard against a stray click in the page. It is not a
security boundary: anyone who can write the policy directory can pause or
resume, which is the same trust as editing the policy.

From a terminal, when no browser is to hand, the command acts at once with no
prompt, and prints exactly what it changed:

```bash
npm run pause -- on --reason "key leaked"            # everything
npm run pause -- on --agent claude                   # one agent
npm run pause -- on --credential github              # one key
npm run pause -- off                                 # resume everything
npm run pause -- status                              # exit code 1 while anything is paused
```

`--yes` is accepted so a script can say plainly that it means it; it changes
nothing.

The switch is the file `pause.json` beside the policy (override with
`BROKER_PAUSE_FILE`). Brokers re-read it on every request, so it needs no
restart, and it fails closed: a missing file means nothing is paused, but a file
that exists and cannot be read pauses everything. Agents are told only that
access is paused and not to retry; your typed reason stays private.

Every pause and resume, from the page or the terminal, appends one line to the
audit log: the scope, the direction, where it came from and when. The reason is
never written there.

**Tamper evidence.** Resuming never deletes `pause.json`; it writes a fresh
file with an explicit resume record. A running broker remembers the last pause
it enforced, so if that pause disappears (the file is deleted, emptied or
replaced) without a matching resume record, the broker stays paused and writes
a `PAUSE_TAMPER` audit line. Only a valid file carrying the resume releases it:
run `npm run pause -- off`, or pause and resume once from the page. This catches
accidents and casual meddling. A hostile process running as the same OS user
can still write a valid file; the real protection against that is the
secure-launch profile in [SECURITY.md](SECURITY.md).

### Hot reload

Set `BROKER_HOT_RELOAD=1` on a broker process and it picks up key manager
changes (a new key, a new API, a changed grant) on the next request, with no
restart. The key manager writes a small marker beside the policy after every
change. If the new policy is invalid, the broker keeps its previous working
state and writes an audit line. Off by default.

Each opt-in control has a short page saying what it does and what it
trusts: [pause](docs/pause.md), [hot reload](docs/hot-reload.md),
[key requests](docs/key-requests.md), [approvals](docs/approvals.md).

### Usage, rotation and approvals

- Each key card shows when it was last used, by which agent, and how its last
  30 days of requests ended, read from the content-free audit log.
- Replacing a key records the date. For known providers a link opens the
  provider's key page so you can revoke the old key.
- The **Approvals** panel creates and revokes approvals for operations the
  policy marks `requires_approval`, with a lifetime of 1 minute to 24 hours.
  It cannot approve anything else, and it never grants write access itself.
- About twenty providers are known (OpenAI, Anthropic, GitHub, Cloudflare,
  Stripe, itch.io and others); picking one fills in the address and key style.

## Running

```bash
npm install
cp config/broker.example.yaml config/broker.yaml   # then edit, or use npm run keys
BROKER_AGENT_ID=researcher npm start
```

Environment:

| Variable | Meaning |
|---|---|
| `BROKER_AGENT_ID` | Identity this stdio session runs as. Required. |
| `BROKER_POLICY_FILE` | Policy path. Default `config/broker.yaml`. |
| `BROKER_AUDIT_FILE` | Audit log path. Default `data/audit.jsonl`. |
| `BROKER_APPROVALS_FILE` | Approval store path. Default `config/approvals.json`. |
| `BROKER_KEYCHAIN` | `off` stops the broker and key manager reading Credential Manager. |
| `BROKER_KEYS_PORT` | Fixed port for `npm run keys`. Default: a free port. |
| `BROKER_KEY_NOTES_FILE` | Expiry dates and notes. Default `key-notes.json` beside the policy. |
| `BROKER_PAUSE_FILE` | The pause switch. Default `pause.json` beside the policy. |
| `BROKER_RELOAD_MARKER` | Hot reload marker. Default `.broker-reload` beside the policy. |
| `BROKER_HOT_RELOAD` | `1` lets a running broker pick up key manager changes. Off by default. |
| `BROKER_ALLOW_KEY_REQUESTS` | `1` enables `broker_request_credential` for this agent. Off by default. |
| *(per credential)* | Each credential's `env_var` carries its secret, overriding a stored key. |

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

## Verification

Run `npm run check` for types, lint and unit tests, `npm run verify:pack`
for the package allowlist, and `npm run test:e2e` for the installed-server
proof. CI runs these on Windows and Linux with Node 22 and 24.

The end-to-end test packs the project, installs the tarball into an empty
directory and starts its declared stdio executable. Synthetic credentials
and a loopback HTTP API exercise tool discovery, principal-scoped grants,
denials before upstream calls, response redaction, metadata-only responses,
approval revocation and content-free audits. It also runs the installed
`credential-broker-pause` binary through pause, status and resume, and
starts `credential-broker-keys`, checks its CSP and token gate, and closes
it. No production credential, OS keychain entry or external API is used.
This does not verify the key manager page in a browser, secure-launch
deployment, independent operator workflows or the eventual npm-hosted
artifact.

Idempotency keys are required and recorded when the policy says so. They
are audit identifiers, not upstream deduplication: the broker neither
forwards them as headers nor suppresses repeated mutations.

The manual release workflow uses Node 24 for the npm trusted-publishing
toolchain and runs the installed proof through `prepublishOnly` before
publication. See [npm's trusted-publisher requirements](https://docs.npmjs.com/trusted-publishers/).
The package's npm trust configuration and the release tag still need
operator verification before a first publish.

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
- [x] Key manager page: provision, replace, test, and remove keys
- [x] Keychain backends for macOS (`security`) and Linux (`secret-tool`),
  unit tested with a faked command runner; real round trips on a Mac and a
  Linux desktop are still to be confirmed by hand
- [ ] Operator CLI: approve, rotate

## Licence

Apache 2.0. See [LICENSE](./LICENSE).
