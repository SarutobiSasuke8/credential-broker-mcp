# Security Policy

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

## Threat model and trust boundary

The broker separates possession of a secret from use of a secret. The agent
process on the other end of the stdio pipe is assumed hostile: it may send
any tool input, and nothing it receives may contain a secret in any
representation the broker created (raw, Base64, base64url,
percent-encoding, form-encoding, NFC/NFD).

What the broker does NOT defend by itself:

- **Launcher identity.** On stdio transport, `BROKER_AGENT_ID` is a
  trusted-launcher assertion, not authentication. The operator who starts
  the process vouches for which agent is connected. This is only a real
  boundary under the secure-launch profile below.
- **Hostile transformations.** An upstream that hashes, encrypts, or
  custom-encodes a secret before echoing it produces output no redactor can
  recognise. Scoped operations and metadata-only responses are the defence,
  not string matching.
- **Host compromise.** Anything running as the same OS user as the broker
  can read whatever the broker can read.

Operator controls added around that boundary, and what they trust:

- **Pause switch.** `pause.json` (beside the policy) is re-read before every
  request. It can only narrow access. A missing file means nothing is paused;
  a file that exists but cannot be read or parsed pauses everything, so a
  corrupted switch never silently re-opens access. The operator's typed reason
  is never relayed to the agent or written to the audit; only the scope is.
  Every pause and resume is audited (scope, direction, source, time).
  Resuming never deletes the file: it writes an explicit resume record, and a
  running broker that saw a pause vanish without one keeps the pause and
  audits `PAUSE_TAMPER`. The typed `PAUSE` and `RESUME` words in the key
  manager guard against accidents, not attackers. Anyone who can write the
  policy directory can pause or resume, which is the same trust as editing the
  policy; a hostile same-user process can forge a valid file, and only the
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
2. **Owner-only files.** Policy file, approvals file, audit log, and any
   `.env` must be readable and writable only by the broker's user. On
   Windows, set explicit ACLs; on POSIX, `chmod 600`.
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
