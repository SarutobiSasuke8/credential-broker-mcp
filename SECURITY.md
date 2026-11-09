# Security Policy

## Threat model on one page

The broker lets an AI agent use an API key without holding it. This page
says what that protects, what it does not, and who you still have to trust.
The detail is in the sections below.

**The attacker the broker is built against** is the agent process on the
other end of the stdio pipe. It is assumed hostile: it may send any tool
input, any URL, any header or body it is allowed to supply, as often as it
likes, and it may be a compromised or prompt-injected model.

**What the broker defends against that attacker**

- It never receives a secret in any representation the broker creates:
  raw, hex, Base64, base64url, percent-encoded, form-encoded, NFC or NFD,
  in a body, a header, an error message, a structured result or an audit
  line. Raw, hex and percent-encoded forms match in any letter case.
- It can only run the operations the policy names for its own identity:
  fixed method, path template, query parameter allowlist, body rules,
  response policy. An absent grant is a denial. Deny rules beat grants.
  Nothing granted for one credential widens another.
- It cannot choose the upstream host. Every request is canonicalised once
  and must stay under the credential's base URL; encoded separators,
  double encoding, backslashes, userinfo, dot segments and control
  characters are rejected outright.
- A denied or dry-run request never reaches the upstream and never touches
  a secret.
- It cannot see or load another agent's secrets: a process loads only the
  credentials granted to its own identity and scrubs them from its
  environment.
- A state-changing operation the policy marks for approval needs an
  approval bound to that agent, credential and operation, checked at
  execution time and revocable mid-flight.
- The operator can stop it at any moment with the pause switch, which only
  narrows access and fails closed.
- Everything it does is audited: who, what, when, outcome. Never content.

**What the broker also defends against: operator accidents**

- A stray click cannot pause or resume everything (typed words).
- A truncated, half-written or deleted pause file cannot silently reopen
  access (fail closed, resume records, tamper evidence).
- An invalid policy during hot reload keeps the previous working state.
- The key manager never grants write access and no endpoint returns a key.

**What the broker does not defend**

- **Anything running as the broker's OS user.** Such a process can read the
  keychain, the policy, the audit log and the broker's memory, set
  `BROKER_AGENT_ID` to any identity, and forge a valid pause file. The
  typed words and the tamper evidence slow an accident, not an attacker.
  The only protection here is the secure-launch profile below: a dedicated
  OS user for the broker, owner-only files, a fixed identity wrapper.
- **What the upstream does with a permitted call.** The broker limits
  method, path, query and body. It does not know what `GET /export` means.
  Grant the smallest operations you can.
- **An upstream that transforms the secret** before echoing it (hash,
  encryption, a custom encoding). No redactor can recognise that. Scoped
  operations and metadata-only responses are the defence.
- **An upstream that echoes part of the secret**, such as the first 12
  characters or a masked `sk_...abcd`. Only whole values are matched: a
  fragment of a credential like `user:password` is an ordinary word, and
  matching it would cut that word out of every response. Metadata-only
  responses are the defence here too.
- **The upstream's own handling of the key.** Once sent, the key is in the
  provider's hands. The policy refuses a base URL that is not `https`
  (plain `http` is allowed on loopback only), and the broker uses TLS as
  Node provides it, with no certificate pinning.
- **Volume.** Apart from key requests, there is no rate limit. An agent
  with a grant can call it as often as the upstream allows.
- **The browser or machine running the key manager.** The page is loopback
  only, token gated and under a strict CSP, but a compromised browser
  profile or desktop can read whatever the operator types.
- **Side channels** such as timing, response size, or the audit log's
  existence of a request.

**Who you must trust**

- The operator, and everything that runs as the operator's OS user (unless
  you run the secure-launch profile, in which case: the broker's user).
- Whoever can write the policy folder: policy, approvals, pause file, hot
  reload marker, key notes.
- The OS keychain: Windows Credential Manager (DPAPI), the macOS login
  keychain, or the Linux Secret Service.
- Node.js, the three runtime dependencies (`@modelcontextprotocol/server`,
  `yaml`, `zod`), and the npm registry with provenance.
- Each upstream API, to keep the key private after it receives it.

If your situation needs more than this (several untrusted users on one
machine, a hosted deployment, regulatory separation of duties), this tool
is not enough on its own.

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's private
vulnerability reporting on this repository (Security tab, "Report a
vulnerability"). Do not open a public issue for anything exploitable.
You should receive an initial response within seven days.

## Supported versions

| Version | Supported |
|---|---|
| `0.1.x` (from the `v0.1.0` tag) | Yes: security fixes land here first. |
| `main` ahead of the latest tag | Best effort. Treat it as a preview. |
| Anything older | No. |

Security fixes are released as a patch of the latest minor line. Node 22
and 24 are the supported runtimes. Nothing has been published to npm until
the `v0.1.0` tag exists; before that, `main` carries no support promise.

## Trust boundary in detail

The broker separates possession of a secret from use of a secret. The agent
process on the other end of the stdio pipe is assumed hostile: it may send
any tool input, and nothing it receives may contain a secret in any
representation the broker created (raw, hex, Base64, base64url,
percent-encoding, form-encoding, NFC/NFD), or that same value in another
letter case.

What the broker does NOT defend by itself:

- **Launcher identity.** On stdio transport, `BROKER_AGENT_ID` is a
  trusted-launcher assertion, not authentication. The operator who starts
  the process vouches for which agent is connected. This is only a real
  boundary under the secure-launch profile below.
- **Hostile transformations.** An upstream that hashes, encrypts, or
  custom-encodes a secret before echoing it produces output no redactor can
  recognise. Nor is a partial echo of a secret matched. Scoped operations
  and metadata-only responses are the defence, not string matching.
- **Host compromise.** Anything running as the same OS user as the broker
  can read whatever the broker can read.

Operator controls added around that boundary, and what they trust:

- **Pause switch.** `pause.json` (beside the policy) is re-read before every
  request. It can only narrow access. A missing file means nothing is paused;
  a file that exists but cannot be read or parsed pauses everything, so a
  corrupted switch never silently re-opens access. The operator's typed reason
  is never relayed to the agent or written to the audit; only the scope is.
  Every pause and resume made through the page or the command is audited
  (scope, direction, source, time). Resuming never deletes the file: it
  writes an explicit resume record. A running broker that sees a pause
  vanish without one keeps the pause and audits `PAUSE_TAMPER`; a release
  that does arrive through the file is audited as `PAUSE_RELEASED`, so a
  release with no matching `RESUME` line stands out. At start-up the broker
  seeds its memory from the audit log, so deleting the file and restarting
  does not quietly resume either. The typed `PAUSE` and `RESUME` words in
  the key manager guard against accidents, not attackers. Anyone who can
  write the policy directory can pause or resume, which is the same trust
  as editing the policy; a hostile same-user process can still forge a
  valid file (it will be audited, not prevented), and only the
  secure-launch profile below prevents that.
- **Hot reload (opt-in, `BROKER_HOT_RELOAD=1`).** A marker file written by the
  key manager makes a running broker rebuild its policy and secrets. It trusts
  whoever can write the policy directory, exactly as start-up does. A reload
  that fails keeps the previous state, and a policy that removes the broker's
  own identity is refused. It cannot change which agent the process is.
- **Agent key requests (opt-in, `BROKER_ALLOW_KEY_REQUESTS=1`).** The agent
  can open the key manager for the operator but never receives its address,
  token or anything typed into it. The base URL comes from the broker's own
  provider table, never from the agent. Requests are rate limited.
- **Key manager.** Listens on loopback only with a per-run token. It never
  grants write access (POST, PUT, PATCH, DELETE). Approvals it creates apply
  only to operations the policy already marks as requiring approval.

## Secure-launch profile (stdio)

Run the broker so the agent cannot simply become someone else:

1. **Dedicated OS identity.** Run the broker under its own OS user (or
   container), not the operator's interactive account and never the same
   identity the agent runs as.
2. **Owner-only files.** Policy file, approvals file, audit log, pause file,
   key notes and any `.env` must be readable and writable only by the
   broker's user. On Windows, set explicit ACLs on the folder: the `0600`
   mode the tools pass when they write is a POSIX permission and does
   nothing on NTFS. On POSIX, `chmod 600` the files and `chmod 700` the
   folder.
3. **Fixed identity wrapper.** Start each agent's broker through a wrapper
   script owned by the broker user that hard-codes `BROKER_AGENT_ID`,
   `BROKER_POLICY_FILE`, `BROKER_AUDIT_FILE`, and `BROKER_APPROVALS_FILE`.
   Agents must not be able to edit the wrapper or supply their own
   environment to the broker process.
4. **No agent-readable secret environment.** Secret variables belong to the
   broker process only. The broker loads just the credentials granted to
   its principal and then scrubs every policy credential variable from its
   own environment, so child processes cannot inherit them.
5. **Minimal filesystem and process access.** The agent must not be able to
   read the broker's memory, its config directory, or its audit location,
   and must not hold debug/trace privileges over the broker process.
6. **Keychain is per OS user.** Keys saved with `npm run keys` live in the
   OS keychain of the account that ran the key manager: Windows Credential
   Manager (DPAPI), the macOS login keychain (`security`), or the Secret
   Service on Linux (`secret-tool`). Any process running as that account
   can read them, as it could a `.env` file. Run the key manager as the
   broker's dedicated user, never as the agent's user. The page binds
   127.0.0.1, requires a per-run token and a loopback Host header, and
   never returns a key. Secrets reach the keychain tools over stdin, never
   as a command-line argument another process could list.
7. **One principal per process.** Never share one broker process between
   agents. Secret material is scoped per principal at load time; separate
   processes keep it that way.

A future HTTP transport must use mutually authenticated, audience-bound,
expiring principal tokens through the same engine, never a caller-selected
agent id.

## Release integrity

Releases are published only through the manual-dispatch GitHub Actions
release workflow using npm trusted publishing (OIDC) with provenance. There
is no long-lived npm token. `prepublishOnly` enforces the full check suite,
a zero-advisory production audit, and a pack allowlist before any publish
can proceed.
