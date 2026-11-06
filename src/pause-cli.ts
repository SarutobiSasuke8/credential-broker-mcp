#!/usr/bin/env node
import { changePause, describeScope, describeState, readPauseFile } from "./pause-admin.js";
import { anyPauseActive, pauseFilePath } from "./kill-switch.js";

import type { PauseScope } from "./kill-switch.js";

/**
 * Terminal version of the panic button, for when a browser is not to hand.
 *
 *   credential-broker-pause on  [--agent id | --credential id] [--reason "text"] [--yes]
 *   credential-broker-pause off [--agent id | --credential id] [--yes]
 *   credential-broker-pause status
 *
 * With no scope it pauses or resumes everything. It acts at once and never
 * asks: in an emergency a prompt is a delay. It prints exactly what it changed,
 * writes the same pause file the key manager does (which every broker re-reads
 * on each request), and appends one content-free line to the audit log.
 * --yes is accepted so a script can say plainly that it means it; it changes
 * nothing. The file is never deleted: resuming writes an explicit record.
 */

const ID = /^[a-z0-9][a-z0-9._-]{1,63}$/u;
const policyFile = process.env.BROKER_POLICY_FILE ?? "config/broker.yaml";
const auditFile = process.env.BROKER_AUDIT_FILE ?? "data/audit.jsonl";
const file = pauseFilePath(policyFile);

function usage(): never {
  console.error('Usage: credential-broker-pause on|off|status [--agent id | --credential id] [--reason "text"] [--yes]');
  process.exit(2);
}

function argValue(args: string[], flag: string): string | undefined {
  const at = args.indexOf(flag);
  return at === -1 ? undefined : args[at + 1];
}

const args = process.argv.slice(2);
const command = args[0];
if (command !== "on" && command !== "off" && command !== "status") usage();

const current = await readPauseFile(file);
if (command === "status") {
  if (current.unreadable) console.log("The pause file exists but cannot be read, so brokers treat everything as paused. Run 'off' to reset it.");
  for (const line of describeState(current.state)) console.log(line);
  process.exit(anyPauseActive(current.state) || current.unreadable ? 1 : 0);
}

const agent = argValue(args, "--agent");
const credential = argValue(args, "--credential");
if (agent && credential) usage();
if ((agent && !ID.test(agent)) || (credential && !ID.test(credential))) {
  console.error("Use a lowercase id: letters, digits, dots, dashes or underscores.");
  process.exit(2);
}
const scope: PauseScope = agent ? { kind: "agent", id: agent } : credential ? { kind: "credential", id: credential } : { kind: "all" };
const active = command === "on";

const result = await changePause({ file, auditFile, source: "cli" }, { scope, active, reason: argValue(args, "--reason") ?? "", undo: false });
const what = describeScope(scope);
if (result.changed) console.log(`Changed: ${what} is now ${active ? "PAUSED" : "resumed"}.`);
else console.log(`No change: ${what} was already ${active ? "paused" : "running"}.`);
if (result.repaired) console.log("The pause file could not be read before, so it was rewritten from a clean state.");
for (const line of describeState(result.after)) console.log(line);
console.log(`Pause file: ${file}`);
