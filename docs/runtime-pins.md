# Runtime pins

This file lists every floating runtime or supply-chain reference in this repository and the exact value each one would be pinned to. It is produced by `scripts/pin-check.mjs`, which runs as the `pin-check` job in CI.

Resolved on 2026-10-16. Nothing in this file has been applied yet: `engines.node` is unchanged.

## Status

- **Node version:** pending gate d48fb4c7. Do not change it until that gate is approved.
- **Docker base image:** none. This repository has no Dockerfile or compose file.
- **Action references:** none floating. Every `uses:` line is already pinned to a full commit SHA.
- **Git dependencies:** none floating. `@sarutobi-sasuke/mcp-eval-harness` is already pinned to commit `077c74a60ccd6d9061e35f882ffd3db5f5d17052`.

## Floating references and proposed pins

| Kind | Location | Current | Proposed pin | Status |
| --- | --- | --- | --- | --- |
| engines.node | `package.json` | `>=22.13` | `22.23.3` (current Node 22 LTS, "Jod", released 2026-09-23) | pending gate d48fb4c7 |

## How the values were resolved

- **Node version:** the newest `v22.*` entry in <https://nodejs.org/dist/index.json> is `v22.23.3` (LTS "Jod", 2026-09-23).
- **Already-pinned actions (for reference):** `actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1` is tag `v7.0.1` (the workflows label it `# v7`; `v7` points to the same commit today), and `actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1` is tag `v7.1.0` (labelled `# v7`, same commit). Confirmed with `gh api repos/actions/<repo>/git/ref/tags/<tag>`.

## Notes

- `engines.node` is a published compatibility range for npm users as well as a runtime pin. When gate d48fb4c7 is decided, pin the runtime in CI and any deployment, and decide separately whether the published range should stay a range.
- The CI matrix `node-version` values (`22`, `24`) also float to the newest patch release. The pin-check script does not report them; they are part of the same gate.
- The `pin-check` job's own checkout step is pinned to a SHA, so it adds no new floating reference.
- This change adds only the CI job, the script and this file. It does not touch broker, credential or auth code.

## Turning the check into a gate

`node scripts/pin-check.mjs` reports and exits 0. `node scripts/pin-check.mjs --strict` (or `PIN_CHECK_STRICT=1`) emits errors and exits 1 when any floating reference remains. Switch the CI step to `--strict` once the pins above are applied.

## Refresh, 27 October 2026

Merged current `main` into the existing proposal without rewriting history. The reporter matches the report-only implementation in agent-handoff-mcp PR #49 at `85ca456a219582b27b7cecd929caa01324cae5c6` (ignoring line endings). It exits 0 with 1 floating reference (`engines.node >=22.13`). The job remains outside the required check aggregate; runtime pins, dependencies and permission logic are unchanged by this proposal.

The pin suggestions above are historical observations from 16 October, not freshly resolved pins. Re-resolve tags and image digests when gate `d48fb4c7` is decided. Marking this report-only proposal ready for review does not approve that gate or apply any pins.
