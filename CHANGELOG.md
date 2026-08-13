# Changelog

All notable changes to this project are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## Unreleased

Nothing in this project has been published to npm yet. Everything below is
unreleased work on `main` towards a first `v0.1.0`.

### Added

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
