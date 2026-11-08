# Pause switch

The pause switch stops agent access without deleting anything. It is always
on: every broker checks it before every request.

## What it does

- Scope: everything, one agent, or one credential. A wider pause beats a
  narrower one. Resuming everything leaves individual pauses in place.
- Takes effect on the next request. No restart.
- Fails closed. A missing file means nothing is paused. A file that exists
  but cannot be read or parsed pauses everything.
- Only narrows access. It can never grant anything the policy does not.
- The agent is told only that access is paused and not to retry. Your
  reason stays in the pause file and is never relayed or audited.

## How to use it

In the key manager: **Pause all access** in the header asks you to type
`PAUSE`; **Resume all access** asks for `RESUME`. Pausing one agent or one
key asks a confirmation and offers an eight second Undo; resuming one asks
a confirmation.

From a terminal, at once and with no prompt:

```bash
npm run pause -- on --reason "key leaked"
npm run pause -- on --agent claude
npm run pause -- on --credential github
npm run pause -- off
npm run pause -- status
```

`status` exits 1 while anything is paused, so a script can check it.
`--yes` is accepted and changes nothing.

## What it trusts

- The file `pause.json` beside the policy (or `BROKER_PAUSE_FILE`). Anyone
  who can write that folder can pause or resume. That is the same trust as
  editing the policy itself.
- The typed words in the page guard against a stray click. They are not a
  security boundary.

## Tamper evidence

Resuming never deletes the file. It writes a fresh file with an explicit
resume record. A running broker remembers the pause it last enforced, so if
that pause disappears (the file is deleted, emptied or replaced) without a
matching resume record, the broker stays paused and writes a
`PAUSE_TAMPER` audit line once. Only a valid file carrying the resume
releases it: run `npm run pause -- off`, or pause and resume from the page.

This catches accidents and casual meddling. A hostile process running as
the same OS user can write a valid file. The protection against that is the
secure-launch profile in [SECURITY.md](../SECURITY.md): a dedicated OS user
for the broker and owner-only permissions on the policy folder.

## Audit

Every pause and resume appends one content-free line to the audit log:

```json
{"at":"...","agentId":"operator","credentialId":"-","method":"PAUSE","host":"broker.local","pathname":"/agent/claude","outcome":"succeeded","detail":"page"}
```

`method` is `PAUSE` or `RESUME`; `pathname` is `/all`, `/agent/<id>` or
`/credential/<id>`; `detail` is `page`, `cli` or `page undo`. A denied
request while paused is audited as `denied` with `paused by operator
(<scope>)`.
