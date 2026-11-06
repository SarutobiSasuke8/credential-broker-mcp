#!/usr/bin/env node
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

import { anyPauseActive, applyPause, EMPTY_PAUSE, parsePauseState, pauseFilePath, serializePauseState } from "./kill-switch.js";

import type { PauseScope, PauseState } from "./kill-switch.js";

/**
 * Terminal version of the panic button, for when a browser is not to hand.
 *
 *   credential-broker-pause on  [--agent id | --credential id] [--reason "text"]
 *   credential-broker-pause off [--agent id | --credential id]
 *   credential-broker-pause status
 *
 * With no scope it pauses or resumes everything. It writes the same pause file
 * the key manager does, which every broker re-reads on each request.
 */

const ID = /^[a-z0-9][a-z0-9._-]{1,63}$/u;
const policyFile = process.env.BROKER_POLICY_FILE ?? "config/broker.yaml";
const file = pauseFilePath(policyFile);

function usage(): never {
  console.error('Usage: credential-broker-pause on|off|status [--agent id | --credential id] [--reason "text"]');
  process.exit(2);
}

function argValue(args: string[], flag: string): string | undefined {
  const at = args.indexOf(flag);
  return at === -1 ? undefined : args[at + 1];
}

async function load(): Promise<{ state: PauseState; unreadable: boolean }> {
  let text: string;
  try {
    text = await readFile(file, "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return { state: EMPTY_PAUSE, unreadable: false };
    return { state: EMPTY_PAUSE, unreadable: true };
  }
  const parsed = parsePauseState(text);
  return parsed.ok ? { state: parsed.state, unreadable: false } : { state: EMPTY_PAUSE, unreadable: true };
}

function describe(state: PauseState): string[] {
  const lines: string[] = [];
  if (state.all) lines.push(`ALL agent access is paused since ${state.all.at}${state.all.reason ? `: ${state.all.reason}` : ""}`);
  for (const [id, entry] of Object.entries(state.agents)) lines.push(`Agent ${id} paused since ${entry.at}${entry.reason ? `: ${entry.reason}` : ""}`);
  for (const [id, entry] of Object.entries(state.credentials)) lines.push(`Credential ${id} paused since ${entry.at}${entry.reason ? `: ${entry.reason}` : ""}`);
  return lines.length ? lines : ["Nothing is paused."];
}

const args = process.argv.slice(2);
const command = args[0];
if (command !== "on" && command !== "off" && command !== "status") usage();

const { state, unreadable } = await load();
if (command === "status") {
  if (unreadable) console.log("The pause file exists but cannot be read, so brokers treat everything as paused. Run 'off' to reset it.");
  for (const line of describe(state)) console.log(line);
  process.exit(anyPauseActive(state) || unreadable ? 1 : 0);
}

const agent = argValue(args, "--agent");
const credential = argValue(args, "--credential");
if (agent && credential) usage();
if ((agent && !ID.test(agent)) || (credential && !ID.test(credential))) {
  console.error("Use a lowercase id: letters, digits, dots, dashes or underscores.");
  process.exit(2);
}
const scope: PauseScope = agent ? { kind: "agent", id: agent } : credential ? { kind: "credential", id: credential } : { kind: "all" };
const next = applyPause(state, scope, command === "on", argValue(args, "--reason") ?? "");

await mkdir(dirname(file), { recursive: true });
const temp = `${file}.tmp-${process.pid}`;
await writeFile(temp, serializePauseState(next), { encoding: "utf8", mode: 0o600 });
await rename(temp, file);
for (const line of describe(next)) console.log(line);
