# Changelog

All notable changes to this project are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## Unreleased

Nothing in this project has been published to npm yet. Everything below is
unreleased work on `main` towards a first `v0.1.0`.

### Added

- Key storage on macOS (login keychain through `security -i`, the secret
  over stdin) and Linux (Secret Service through `secret-tool`), behind the
  same `SecretStore` interface as Windows, picked by platform. All three
  stores run through one command-runner seam and are unit tested with a
  fake. CI now also runs on macOS. Real round trips on a Mac and a Linux
  desktop remain a manual check.
- Release plumbing for `v0.1.0`: `mcpName` in `package.json` and a
  `server.json` for the MCP Registry, checked against each other by a test.
  The installed-package proof now also runs the `credential-broker-pause`
  binary through pause, status and resume, and starts and closes
  `credential-broker-keys`. Dependabot updates are grouped.
- Community files: `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, issue and pull
  request templates, and a supported-versions table in `SECURITY.md`.
- Docs: a five-minute quickstart at the top of the README, the
  `broker_request_credential` tool in the tools table, every `BROKER_*`
  variable in the environment table, and a `docs/` page for each opt-in
  control (pause, hot reload, key requests, approvals).
- The key manager creates the policy folder when `BROKER_POLICY_FILE`
  points somewhere new.
- Pause safeguards. Pausing everything asks you to type `PAUSE` and resuming
  everything asks for `RESUME`; pausing one agent or key confirms and offers an
  eight second Undo; resuming one confirms. Every pause and resume, from the
  page or `npm run pause`, writes a content-free audit line. Resuming never
  deletes `pause.json`, and a running broker that sees an active pause vanish
  without a resume record stays paused and audits `PAUSE_TAMPER`. The terminal
  command stays immediate, accepts `--yes`, and prints exactly what changed.
- Panic button: a pause switch (`pause.json`) checked before every request, for
  everything, one agent or one key. One click in the key manager, or
  `npm run pause`. Fails closed (an unreadable file pauses everything), needs no
  restart, outranks every grant, and never relays the operator's reason to the
  agent or the audit. Adds the `operator-pause` deciding rule.
- Opt-in hot reload (`BROKER_HOT_RELOAD=1`): the key manager writes a marker
  after each change and a running broker rebuilds its policy and secrets. A
  failed reload keeps the previous state and is audited.
- Key manager: last-used and 30-day outcome counts per key from the audit log,
  key replacement dates, provider key-page links, an Approvals panel (create and
  revoke approvals for operations that already require one), per-agent and
  per-key pause, and about twenty known providers.
- Opt-in `broker_request_credential` tool (`BROKER_ALLOW_KEY_REQUESTS=1`):
  an agent can ask the operator for a key. The broker opens the key manager
  in the operator's browser, pre-filled with the name, the agent's reason and
  a provider from the broker's own table. The agent never sees the page
  address, token or entered value, cannot choose the base URL, and is rate
  limited (one per credential per 10 minutes, five an hour). Adds an itch.io
  provider preset.
- Key manager redesign: Add a key first, a summary strip, a searchable and
  filterable key list sorted by urgency, and optional expiry dates and notes
  per key kept in `key-notes.json` beside the policy.
- Clean-tarball stdio proof with a synthetic loopback API, checking
  principal grants, rejected requests, redacted responses, metadata-only
  output, approval revocation and audit contents. CI covers Windows/Linux
  on Node 22/24; publication requires this proof.

- Key manager (`npm run keys`): a local page for adding APIs, saving,
  replacing, testing, and removing keys without touching environment
  variables. Keys are stored in Windows Credential Manager; the broker
  reads any granted credential the environment leaves unset from there
  (`loadPrincipalSecrets`). The page only ever grants read access and
  validates every policy edit with the broker's own parser, keeping
  comments and a `.bak` of the previous file. "Find my keys" imports keys
  already on the machine (user environment, MCP configs, `.env` files)
  without the values ever reaching the page or the originals being edited.
- Canonical request model: every URL is parsed once into an immutable
  canonical value; encoded separators, double encoding, controls,
  backslashes, userinfo, non-ASCII path segments, repeated and trailing
  slashes, and trailing-dot segments are rejected outright. Policy and
  execution consume only the canonical form, with a round-trip check on the
  exact outbound bytes. (#1)
- Policy v2: per-credential named operation grants with fixed method, path
  template, query parameter allowlist, body rules, response policy,
  approval and idempotency requirements. Deny-by-default at every level;
  nothing granted for one credential widens another. Deterministic
  v1-to-v2 migration tool (`npm run migrate`). (#2)
- Central `SecretRedactor` covering raw, NFC/NFD, Base64, base64url,
  percent-encoded, and form-encoded secret representations, applied to
  response bodies, relayed headers, error chains, and every audit record;
  truncation cannot leak a partial secret. Query-string credentials must be
  explicitly marked `high_risk`. Responses default to metadata only;
  relaying a body is an explicit per-operation grant with a content-type
  allowlist. (#3)
- `BrokerEngine`: the only path from request to upstream, binding one
  authenticated principal with `SecretProvider`, `ApprovalStore`,
  `AuditSink`, and `Clock` seams. Env-backed secrets load only the
  principal's credentials and scrub policy variables from the process
  environment. Raw execution is no longer exported. Secure-launch profile
  documented in SECURITY.md. (#4)
- Read/mutation tool split: `broker_read` (GET/HEAD, honestly read-only)
  and `broker_mutate` (POST/PUT/PATCH/DELETE, annotated destructive and
  non-idempotent). Mutations can require approvals checked at execution
  time against a live store (expiry and revocation take effect mid-flight)
  and idempotency keys. Audit records the full lifecycle: requested,
  approved, denied, executing, succeeded, failed, indeterminate. (#5)
- Release engineering: `prepublishOnly` gates (check, production audit,
  pack allowlist), pinned GitHub Actions, least-privilege workflow
  permissions, manual-dispatch OIDC trusted-publishing release workflow,
  Dependabot, SECURITY.md. (#6)

### Changed

- Reject unknown fields throughout policy v2. Misspelt disabling and deny
  settings now stop startup instead of silently losing their restrictions.
  Existing deployments must correct ignored fields before upgrading.
- Use Node 24 for npm trusted publishing and pass the selected release tag
  through an environment variable when checking the package version.

- Package moved to the `@sarutobi-sasuke` npm scope with full publish
  metadata.
- `broker_request` replaced by `broker_read` and `broker_mutate`.
- Policy files must be version 2; version 1 files are refused with
  migration guidance.
- README safety claims rewritten to state exactly what is and is not
  defended.

### Removed

- Direct `minimatch` dependency (previously upgraded to 10.2.6 to clear
  the ReDoS advisory ranges, now removed entirely in favour of exact
  segment templates).
- The `./gateway` package export: upstream execution is engine-internal so
  it cannot be exercised without policy, principal, and audit.
