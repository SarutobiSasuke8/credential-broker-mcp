import assert from "node:assert/strict";
import test from "node:test";

import { KEYCHAIN_PREFIX, LibSecretStore, MacKeychainStore, MAX_SECRET_BYTES, platformSecretStore, quoteForSecurity, WindowsCredentialStore } from "../src/keychain.js";

import type { CommandResult, CommandRunner } from "../src/keychain.js";

const SECRET = "synthetic-key-value-0123456789";

interface Call {
  command: string;
  args: readonly string[];
  stdin: string | undefined;
}

/** A fake runner: records every call and answers from a script. */
function fakeRunner(answer: (call: Call) => Partial<CommandResult>): { runner: CommandRunner; calls: Call[] } {
  const calls: Call[] = [];
  return {
    calls,
    runner: {
      run(command, args, stdin) {
        const call = { command, args, stdin };
        calls.push(call);
        return Promise.resolve({ code: 0, stdout: "", stderr: "", ...answer(call) });
      },
    },
  };
}

function everything(calls: Call[]): string {
  return JSON.stringify(calls.map((c) => [c.command, c.args]));
}

// ---- platform selection ----------------------------------------------------

void test("the platform picks the store, and BROKER_KEYCHAIN=off switches every platform off", () => {
  assert.equal(platformSecretStore({}, "win32")?.name, "Windows Credential Manager");
  assert.equal(platformSecretStore({}, "darwin")?.name, "macOS Keychain");
  assert.equal(platformSecretStore({}, "linux")?.name, "Secret Service (libsecret)");
  assert.equal(platformSecretStore({}, "freebsd"), null);
  for (const platform of ["win32", "darwin", "linux"] as const) {
    assert.equal(platformSecretStore({ BROKER_KEYCHAIN: "OFF" }, platform), null);
  }
});

// ---- macOS -----------------------------------------------------------------

void test("macOS: the secret goes to `security -i` over stdin, never on the command line, with safe quoting", async () => {
  const { runner, calls } = fakeRunner(() => ({ code: 0 }));
  const store = new MacKeychainStore(runner);
  const tricky = 'pa"ss\\word with spaces';
  await store.set("github", tricky, 'from "Documents"');
  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0]?.args, ["-i"]);
  assert.doesNotMatch(everything(calls), /pa"ss/u, "the value is not an argument");
  const line = calls[0]?.stdin ?? "";
  assert.match(line, /^add-generic-password -U -a "credential-broker" -s "credential-broker\/github" -j "from \\"Documents\\"" -w "pa\\"ss\\\\word with spaces"\n$/u);
  assert.equal(quoteForSecurity('a"b\\c'), '"a\\"b\\\\c"');
  await assert.rejects(store.set("bad id", SECRET), /Invalid credential id/u);
  await assert.rejects(store.set("github", ""), /empty/u);
  await assert.rejects(store.set("github", "x".repeat(MAX_SECRET_BYTES + 1)), /longer/u);
});

void test("macOS: lookups read stdout, treat exit 44 as absent, and never relay stderr", async () => {
  const { runner, calls } = fakeRunner(({ args }) => {
    if (args[0] !== "find-generic-password") return { code: 0 };
    const service = args[args.indexOf("-s") + 1];
    if (service === `${KEYCHAIN_PREFIX}github`) return { code: 0, stdout: `${SECRET}\n` };
    if (service === `${KEYCHAIN_PREFIX}broken`) return { code: 1, stderr: `security: SecKeychainSearchCopyNext: ${SECRET}` };
    return { code: 44, stderr: "security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain." };
  });
  const store = new MacKeychainStore(runner);
  const found = await store.getMany(["github", "missing"]);
  assert.deepEqual([...found], [["github", SECRET]]);
  assert.ok(calls.every((c) => c.args.includes("-w")), "asks for the password data only");
  await assert.rejects(store.getMany(["broken"]), (error: Error) => {
    assert.doesNotMatch(error.message, new RegExp(SECRET, "u"));
    return /Keychain call failed/u.test(error.message);
  });
});

void test("macOS: delete reports whether something was removed, and list parses dump-keychain attributes only", async () => {
  const dump = [
    'keychain: "/Users/me/Library/Keychains/login.keychain-db"',
    "version: 512",
    'class: "genp"',
    "attributes:",
    '    0x00000007 <blob>="credential-broker/github"',
    '    "acct"<blob>="credential-broker"',
    '    "icmt"<blob>="Imported from GITHUB_TOKEN: .env"',
    '    "svce"<blob>="credential-broker/github"',
    'keychain: "/Users/me/Library/Keychains/login.keychain-db"',
    "version: 512",
    'class: "genp"',
    "attributes:",
    '    "acct"<blob>="credential-broker"',
    '    "icmt"<blob>=<NULL>',
    '    "svce"<blob>="credential-broker/openai"',
    'keychain: "/Users/me/Library/Keychains/login.keychain-db"',
    'class: "genp"',
    "attributes:",
    '    "acct"<blob>="someone-else"',
    '    "svce"<blob>="credential-broker/not-ours"',
    'keychain: "/Users/me/Library/Keychains/login.keychain-db"',
    'class: "inet"',
    "attributes:",
    '    "acct"<blob>="credential-broker"',
    '    "svce"<blob>="credential-broker/website"',
    "",
  ].join("\n");
  const { runner } = fakeRunner(({ args }) => {
    if (args[0] === "dump-keychain") return { code: 0, stdout: dump };
    if (args[0] === "delete-generic-password") return { code: args.includes(`${KEYCHAIN_PREFIX}github`) ? 0 : 44 };
    return { code: 0 };
  });
  const store = new MacKeychainStore(runner);
  assert.deepEqual(await store.list(), [
    { id: "github", comment: "Imported from GITHUB_TOKEN: .env" },
    { id: "openai", comment: "" },
  ]);
  assert.equal(await store.delete("github"), true);
  assert.equal(await store.delete("missing"), false);
});

void test("macOS: a missing security binary gives a clear error", async () => {
  const { runner } = fakeRunner(() => ({ code: null, spawnError: "ENOENT" }));
  await assert.rejects(new MacKeychainStore(runner).list(), /could not be started/u);
});

// ---- Linux -----------------------------------------------------------------

void test("Linux: store sends the secret on stdin with a label carrying the comment, and the same attributes replace the item", async () => {
  const { runner, calls } = fakeRunner(() => ({ code: 0 }));
  const store = new LibSecretStore(runner);
  await store.set("github", SECRET, "read only");
  assert.deepEqual(calls[0]?.args, ["store", "--label=credential-broker/github: read only", "service", "credential-broker", "id", "github"]);
  assert.equal(calls[0]?.stdin, SECRET);
  assert.doesNotMatch(everything(calls), new RegExp(SECRET, "u"));
  await store.set("github", SECRET);
  assert.deepEqual(calls[1]?.args, ["store", "--label=credential-broker/github", "service", "credential-broker", "id", "github"]);
});

void test("Linux: lookup, delete and search behave like secret-tool does", async () => {
  const search = [
    "[/org/freedesktop/secrets/collection/login/12]",
    "label = credential-broker/github: read only",
    "secret = should-not-be-used",
    "created = 2026-11-06 10:00:00",
    "modified = 2026-11-06 10:00:00",
    "schema = org.freedesktop.Secret.Generic",
    "attribute.service = credential-broker",
    "attribute.id = github",
    "",
    "[/org/freedesktop/secrets/collection/login/13]",
    "label = credential-broker/openai",
    "secret = other",
    "attribute.service = credential-broker",
    "attribute.id = openai",
    "",
    "[/org/freedesktop/secrets/collection/login/14]",
    "label = unrelated",
    "attribute.service = credential-broker",
    "attribute.id = Not Valid",
    "",
  ].join("\n");
  const { runner, calls } = fakeRunner(({ args }) => {
    if (args[0] === "lookup") return args.includes("github") ? { code: 0, stdout: SECRET } : { code: 1 };
    if (args[0] === "search") return { code: 0, stdout: search };
    return { code: 0 };
  });
  const store = new LibSecretStore(runner);
  assert.deepEqual([...(await store.getMany(["github", "missing"]))], [["github", SECRET]]);
  assert.deepEqual(await store.list(), [
    { id: "github", comment: "read only" },
    { id: "openai", comment: "" },
  ]);
  assert.equal(await store.delete("github"), true);
  assert.ok(calls.some((c) => c.args[0] === "clear" && c.args.includes("github")));
  const before = calls.length;
  assert.equal(await store.delete("missing"), false);
  assert.ok(!calls.slice(before).some((c) => c.args[0] === "clear"), "nothing to clear for a missing key");
});

void test("Linux: no daemon and no binary are reported plainly, without relaying stderr", async () => {
  const noDaemon = fakeRunner(() => ({ code: 1, stderr: `secret-tool: ${SECRET} The name org.freedesktop.secrets was not provided` }));
  await assert.rejects(new LibSecretStore(noDaemon.runner).set("github", SECRET), (error: Error) => {
    assert.doesNotMatch(error.message, new RegExp(SECRET, "u"));
    return /keyring daemon/u.test(error.message);
  });
  const noBinary = fakeRunner(() => ({ code: null, spawnError: "ENOENT" }));
  await assert.rejects(new LibSecretStore(noBinary.runner).list(), /not installed/u);
});

// ---- Windows through the same seam -----------------------------------------

void test("Windows: the request goes to a fixed encoded script over stdin, and failures use a fixed message", async () => {
  const { runner, calls } = fakeRunner(({ stdin }) => {
    const request = JSON.parse(stdin ?? "{}") as { op: string };
    if (request.op === "get") return { code: 0, stdout: JSON.stringify({ values: { "credential-broker/github": SECRET } }) };
    if (request.op === "list") return { code: 0, stdout: JSON.stringify({ targets: ["credential-broker/github\u0001note", "other/thing\u0001x"] }) };
    if (request.op === "delete") return { code: 0, stdout: JSON.stringify({ ok: true }) };
    return { code: 1, stderr: `error ${SECRET}` };
  });
  const store = new WindowsCredentialStore(runner);
  assert.deepEqual([...(await store.getMany(["github"]))], [["github", SECRET]]);
  assert.equal(calls[0]?.command, "powershell.exe");
  assert.ok(calls[0]?.args.includes("-EncodedCommand"));
  assert.doesNotMatch(everything(calls), new RegExp(SECRET, "u"));
  assert.deepEqual(await store.list(), [{ id: "github", comment: "note" }]);
  assert.equal(await store.delete("github"), true);
  await assert.rejects(store.set("github", SECRET), (error: Error) => {
    assert.doesNotMatch(error.message, new RegExp(SECRET, "u"));
    return /call failed/u.test(error.message);
  });
});
