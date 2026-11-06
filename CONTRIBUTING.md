# Contributing

Thank you for looking at this project. It is small and security-focused, so
the bar for changes is "does this keep the boundary honest", not "does this
add a feature".

## Before you start

- Read [SECURITY.md](SECURITY.md) first. It states what the broker defends,
  what it does not, and who must be trusted. A change that moves that line
  needs a discussion in an issue before a pull request.
- Found a vulnerability? Do not open a public issue. Use the private route
  in SECURITY.md.
- Supported Node versions are 22 and 24. CI runs both on Windows and Linux.

## Setting up

```bash
git clone https://github.com/SarutobiSasuke8/credential-broker-mcp.git
cd credential-broker-mcp
npm ci
npm run check
```

`npm run check` runs the typecheck, the linter and the unit tests. Before
opening a pull request also run:

```bash
npm run verify:pack
```

```bash
npm run test:e2e
```

The first proves the published tarball holds only what the allowlist in
`scripts/verify-pack.mjs` permits. The second installs that tarball in a
clean folder and drives the real binaries.

## Rules that every change must keep

- A secret never reaches an agent in any representation the broker creates.
- Deny by default. An absent grant is a denial. Deny rules beat grants.
- Nothing widens sideways: a rule on one credential never loosens another.
- The audit log stays content-free. Never record a query string, a body or a
  response.
- The key manager never grants write access and no endpoint ever returns a
  key.
- Operator controls (pause, hot reload, key requests, approvals) only ever
  narrow or gate access. They fail closed.
- Opt-in controls stay opt-in, by environment variable.
- No new runtime dependency without a very good reason. The dependency list
  is three packages on purpose.
- The key manager page stays self-contained under its strict CSP: no
  external scripts, styles, fonts or images.

## Writing a change

- Keep commits small and the commit message plain: what changed and why.
- Add a test for every rule you add or touch. Pure logic goes in `test/`;
  behaviour of the real binaries goes in `scripts/packaged-stdio.test.mjs`.
- Update `CHANGELOG.md` under `Unreleased`.
- Copy and docs: British English, short plain sentences, readable by
  non-native speakers. No em dashes.
- Never paste a real key, a real policy, or a private path into code, tests,
  docs, issues or pull requests. Tests use synthetic values.

## Pull requests

Fill in the template. Say what you verified and what you did not. A pull
request that changes a security-relevant path (`engine.ts`, `canonical.ts`,
`redact.ts`, `policy.ts`, `keychain.ts`, `kill-switch.ts`, `keys-ui.ts`)
should explain the threat it addresses or the reason it cannot weaken one.

CI must be green on every platform before a merge.

## Releases

Releases are manual. The maintainer tags `vX.Y.Z` and runs the Release
workflow, which publishes to npm with provenance through trusted publishing.
Contributors do not need to do anything for a release.
