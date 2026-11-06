import { execFile } from "node:child_process";

/**
 * OS keychain storage for credential secrets, so operators paste a key once
 * into a local form instead of editing environment variables or .env files.
 *
 * - Windows: Credential Manager, generic credentials named
 *   `credential-broker/<credential-id>`, encrypted by DPAPI under the
 *   operator's account (Control Panel > Credential Manager > Windows
 *   Credentials).
 * - macOS: the login keychain through the `security` command, generic
 *   passwords with service `credential-broker/<credential-id>`.
 * - Linux: the Secret Service (GNOME Keyring, KWallet and others) through
 *   `secret-tool` from libsecret, attributes `service=credential-broker`
 *   and `id=<credential-id>`.
 *
 * Secrets never travel on a command line, where another process could read
 * them: Windows and macOS take them over stdin, and secret-tool reads the
 * value from stdin by design.
 *
 * This is a convenience store, not a boundary. Any process running as the
 * same OS user can read the keychain, exactly as it can read a .env file.
 * The secure-launch profile in SECURITY.md (dedicated OS user for the
 * broker) still applies; run the key manager as that user.
 */

export interface SecretStore {
  /** Operator-facing name, e.g. "Windows Credential Manager". */
  readonly name: string;
  /** Values for the requested credential ids. Absent ids are omitted. */
  getMany(credentialIds: readonly string[]): Promise<Map<string, string>>;
  /** Comment is a non-secret note, e.g. where an imported key came from. */
  set(credentialId: string, value: string, comment?: string): Promise<void>;
  /** True if a stored secret was removed. */
  delete(credentialId: string): Promise<boolean>;
  /** Credential ids that currently have a stored secret, with their comments. */
  list(): Promise<StoredKey[]>;
}

export interface StoredKey {
  id: string;
  comment: string;
}

export const KEYCHAIN_PREFIX = "credential-broker/";

/**
 * Credential Manager caps a blob at 2560 bytes. Blobs are stored as UTF-8 so
 * that covers 2560 ASCII characters, enough for API keys, PATs, and JWTs.
 * The same cap applies on every platform so a key that fits on one machine
 * fits on all of them.
 */
export const MAX_SECRET_BYTES = 2560;

/** Comments are capped on Windows at 256 characters; the cap applies everywhere. */
const MAX_COMMENT = 250;

const CREDENTIAL_ID_PATTERN = /^[a-z0-9][a-z0-9._-]{1,63}$/u;

function assertId(credentialId: string): string {
  if (!CREDENTIAL_ID_PATTERN.test(credentialId)) throw new Error(`Invalid credential id '${credentialId}'.`);
  return credentialId;
}

function targetFor(credentialId: string): string {
  return `${KEYCHAIN_PREFIX}${assertId(credentialId)}`;
}

function checkValue(value: string): void {
  if (value.length === 0) throw new Error("Refusing to store an empty secret.");
  if (Buffer.byteLength(value, "utf8") > MAX_SECRET_BYTES) {
    throw new Error(`Secret is longer than the keychain allows (${MAX_SECRET_BYTES} bytes).`);
  }
}

// ---------------------------------------------------------------------------
// Command runner seam, so every store can be tested with a fake
// ---------------------------------------------------------------------------

export interface CommandResult {
  /** Exit code, or null when the process was killed or could not start. */
  code: number | null;
  stdout: string;
  stderr: string;
  /** Set when the executable could not be started at all (ENOENT and friends). */
  spawnError?: string;
}

export interface CommandRunner {
  run(command: string, args: readonly string[], stdin?: string): Promise<CommandResult>;
}

/** Runs the command with stdin from memory. Output is capped and the call times out. */
export const execFileRunner: CommandRunner = {
  run(command, args, stdin) {
    return new Promise((resolve) => {
      const child = execFile(
        command,
        [...args],
        { windowsHide: true, maxBuffer: 4 * 1024 * 1024, timeout: 30_000, encoding: "utf8" },
        (error, stdout, stderr) => {
          if (!error) {
            resolve({ code: 0, stdout, stderr });
            return;
          }
          // execFile reports a non-zero exit as a numeric code, and a process
          // that could not start (ENOENT) or was killed (timeout) otherwise.
          const code = (error as { code?: unknown }).code;
          if (typeof code === "string") resolve({ code: null, stdout, stderr, spawnError: code });
          else resolve({ code: typeof code === "number" ? code : null, stdout, stderr });
        },
      );
      child.stdin?.end(stdin ?? "", "utf8");
    });
  },
};

// ---------------------------------------------------------------------------
// Windows: Credential Manager through a fixed PowerShell script
// ---------------------------------------------------------------------------

// P/Invoke over advapi32 so no native Node module is needed. The script is
// fixed and passed with -EncodedCommand; secrets travel only over stdin and
// stdout, never on a command line another process could read.
const WINDOWS_SCRIPT = String.raw`
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class CbCred {
  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
  struct CREDENTIAL {
    public int Flags; public int Type; public string TargetName; public string Comment;
    public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
    public int CredentialBlobSize; public IntPtr CredentialBlob; public int Persist;
    public int AttributeCount; public IntPtr Attributes; public string TargetAlias; public string UserName;
  }
  [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  static extern bool CredReadW(string target, int type, int flags, out IntPtr cred);
  [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  static extern bool CredWriteW(ref CREDENTIAL cred, int flags);
  [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  static extern bool CredDeleteW(string target, int type, int flags);
  [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  static extern bool CredEnumerateW(string filter, int flags, out int count, out IntPtr creds);
  [DllImport("advapi32.dll")]
  static extern void CredFree(IntPtr p);
  public static string Read(string target) {
    IntPtr p;
    if (!CredReadW(target, 1, 0, out p)) return null;
    try {
      CREDENTIAL c = (CREDENTIAL)Marshal.PtrToStructure(p, typeof(CREDENTIAL));
      byte[] b = new byte[c.CredentialBlobSize];
      if (b.Length > 0) Marshal.Copy(c.CredentialBlob, b, 0, b.Length);
      return Encoding.UTF8.GetString(b);
    } finally { CredFree(p); }
  }
  public static void Write(string target, string value, string comment) {
    byte[] b = Encoding.UTF8.GetBytes(value);
    CREDENTIAL c = new CREDENTIAL();
    c.Type = 1; c.TargetName = target; c.UserName = "credential-broker"; c.Persist = 2; c.Comment = comment;
    c.CredentialBlobSize = b.Length; c.CredentialBlob = Marshal.AllocHGlobal(b.Length);
    try {
      Marshal.Copy(b, 0, c.CredentialBlob, b.Length);
      if (!CredWriteW(ref c, 0)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
    } finally { Marshal.FreeHGlobal(c.CredentialBlob); }
  }
  public static bool Delete(string target) { return CredDeleteW(target, 1, 0); }
  public static string[] List(string filter) {
    int n; IntPtr p;
    if (!CredEnumerateW(filter, 0, out n, out p)) return new string[0];
    try {
      string[] r = new string[n];
      for (int i = 0; i < n; i++) {
        IntPtr cp = Marshal.ReadIntPtr(p, i * IntPtr.Size);
        CREDENTIAL c = (CREDENTIAL)Marshal.PtrToStructure(cp, typeof(CREDENTIAL));
        r[i] = c.TargetName + "\u0001" + (c.Comment ?? "");
      }
      return r;
    } finally { CredFree(p); }
  }
}
"@
$req = [Console]::In.ReadToEnd() | ConvertFrom-Json
$out = @{}
switch ($req.op) {
  'get'    { $v = @{}; foreach ($t in $req.targets) { $s = [CbCred]::Read($t); if ($null -ne $s) { $v[$t] = $s } }; $out.values = $v }
  'set'    { [CbCred]::Write($req.target, $req.value, [string]$req.comment); $out.ok = $true }
  'delete' { $out.ok = [CbCred]::Delete($req.target) }
  'list'   { $out.targets = @([CbCred]::List($req.filter)) }
}
[Console]::Out.Write(($out | ConvertTo-Json -Compress -Depth 4))
`;

const ENCODED_WINDOWS_SCRIPT = Buffer.from(WINDOWS_SCRIPT, "utf16le").toString("base64");

export class WindowsCredentialStore implements SecretStore {
  public readonly name = "Windows Credential Manager";

  public constructor(private readonly runner: CommandRunner = execFileRunner) {}

  private async call(request: object): Promise<Record<string, unknown>> {
    const result = await this.runner.run(
      "powershell.exe",
      ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", ENCODED_WINDOWS_SCRIPT],
      JSON.stringify(request),
    );
    // stderr may echo the request on some failures, so it is never relayed:
    // callers get a fixed message.
    if (result.code !== 0) throw new Error("Windows Credential Manager call failed.");
    try {
      return JSON.parse(result.stdout) as Record<string, unknown>;
    } catch {
      throw new Error("Windows Credential Manager returned unreadable output.");
    }
  }

  public async getMany(credentialIds: readonly string[]): Promise<Map<string, string>> {
    const result = new Map<string, string>();
    if (credentialIds.length === 0) return result;
    const response = await this.call({ op: "get", targets: credentialIds.map(targetFor) });
    const values = (response.values ?? {}) as Record<string, unknown>;
    for (const id of credentialIds) {
      const value = values[targetFor(id)];
      if (typeof value === "string" && value.length > 0) result.set(id, value);
    }
    return result;
  }

  public async set(credentialId: string, value: string, comment = ""): Promise<void> {
    checkValue(value);
    await this.call({ op: "set", target: targetFor(credentialId), value, comment: comment.slice(0, MAX_COMMENT) });
  }

  public async delete(credentialId: string): Promise<boolean> {
    const response = await this.call({ op: "delete", target: targetFor(credentialId) });
    return response.ok === true;
  }

  public async list(): Promise<StoredKey[]> {
    const response = await this.call({ op: "list", filter: `${KEYCHAIN_PREFIX}*` });
    const targets = Array.isArray(response.targets) ? response.targets : [];
    return targets
      .filter((t): t is string => typeof t === "string" && t.startsWith(KEYCHAIN_PREFIX))
      .map((t) => {
        const [target = "", comment = ""] = t.split("\u0001");
        return { id: target.slice(KEYCHAIN_PREFIX.length), comment };
      });
  }
}

// ---------------------------------------------------------------------------
// macOS: the login keychain through `security`
// ---------------------------------------------------------------------------

const MAC_ACCOUNT = "credential-broker";
/** errSecItemNotFound, the exit status `security` uses for a missing item. */
const MAC_NOT_FOUND = 44;

/**
 * Quotes one argument for `security -i`, whose interactive reader accepts
 * double-quoted strings with backslash escapes. Only backslash and the
 * double quote need escaping; everything else is literal inside the quotes.
 */
export function quoteForSecurity(value: string): string {
  return `"${value.replace(/\\/gu, "\\\\").replace(/"/gu, '\\"')}"`;
}

/** Pulls `"svce"<blob>="..."` style attributes out of one dump-keychain item. */
function dumpAttribute(block: string, key: string): string | null {
  const hit = new RegExp(`"${key}"<blob>=(?:"((?:[^"\\\\]|\\\\.)*)"|<NULL>)`, "u").exec(block);
  if (!hit) return null;
  return hit[1] === undefined ? "" : hit[1].replace(/\\(.)/gu, "$1");
}

export class MacKeychainStore implements SecretStore {
  public readonly name = "macOS Keychain";

  public constructor(private readonly runner: CommandRunner = execFileRunner) {}

  private async security(args: readonly string[], stdin?: string): Promise<CommandResult> {
    const result = await this.runner.run("security", args, stdin);
    if (result.spawnError) throw new Error("The macOS 'security' command could not be started.");
    return result;
  }

  public async getMany(credentialIds: readonly string[]): Promise<Map<string, string>> {
    const out = new Map<string, string>();
    for (const id of credentialIds) {
      const result = await this.security(["find-generic-password", "-a", MAC_ACCOUNT, "-s", targetFor(id), "-w"]);
      if (result.code === MAC_NOT_FOUND) continue;
      if (result.code !== 0) throw new Error("macOS Keychain call failed.");
      const value = result.stdout.replace(/\r?\n$/u, "");
      if (value.length > 0) out.set(id, value);
    }
    return out;
  }

  public async set(credentialId: string, value: string, comment = ""): Promise<void> {
    checkValue(value);
    // Interactive mode reads the command from stdin, so the secret is never
    // an argument of a process that `ps` could show. -U updates in place.
    const line = [
      "add-generic-password",
      "-U",
      "-a", quoteForSecurity(MAC_ACCOUNT),
      "-s", quoteForSecurity(targetFor(credentialId)),
      "-j", quoteForSecurity(comment.slice(0, MAX_COMMENT)),
      "-w", quoteForSecurity(value),
    ].join(" ");
    const result = await this.security(["-i"], `${line}\n`);
    if (result.code !== 0) throw new Error("macOS Keychain call failed.");
  }

  public async delete(credentialId: string): Promise<boolean> {
    const result = await this.security(["delete-generic-password", "-a", MAC_ACCOUNT, "-s", targetFor(credentialId)]);
    if (result.code === MAC_NOT_FOUND) return false;
    if (result.code !== 0) throw new Error("macOS Keychain call failed.");
    return true;
  }

  public async list(): Promise<StoredKey[]> {
    // dump-keychain prints attributes only, never the password data.
    const result = await this.security(["dump-keychain"]);
    if (result.code !== 0) throw new Error("macOS Keychain call failed.");
    const out: StoredKey[] = [];
    for (const block of result.stdout.split(/^keychain: /mu)) {
      if (!/^class: "genp"/mu.test(block)) continue;
      const service = dumpAttribute(block, "svce");
      if (!service?.startsWith(KEYCHAIN_PREFIX)) continue;
      if (dumpAttribute(block, "acct") !== MAC_ACCOUNT) continue;
      const id = service.slice(KEYCHAIN_PREFIX.length);
      if (!CREDENTIAL_ID_PATTERN.test(id)) continue;
      out.push({ id, comment: dumpAttribute(block, "icmt") ?? "" });
    }
    return out.sort((a, b) => a.id.localeCompare(b.id));
  }
}

// ---------------------------------------------------------------------------
// Linux: the Secret Service through `secret-tool` (libsecret)
// ---------------------------------------------------------------------------

const LINUX_SERVICE = "credential-broker";

function linuxLabel(credentialId: string, comment: string): string {
  return comment ? `${KEYCHAIN_PREFIX}${credentialId}: ${comment}` : `${KEYCHAIN_PREFIX}${credentialId}`;
}

export class LibSecretStore implements SecretStore {
  public readonly name = "Secret Service (libsecret)";

  public constructor(private readonly runner: CommandRunner = execFileRunner) {}

  private async tool(args: readonly string[], stdin?: string): Promise<CommandResult> {
    const result = await this.runner.run("secret-tool", args, stdin);
    if (result.spawnError) {
      throw new Error("secret-tool is not installed. Install libsecret-tools (Debian, Ubuntu) or libsecret (Fedora, Arch), or set BROKER_KEYCHAIN=off and use environment variables.");
    }
    return result;
  }

  private async lookup(credentialId: string): Promise<string | null> {
    const result = await this.tool(["lookup", "service", LINUX_SERVICE, "id", assertId(credentialId)]);
    // secret-tool exits 1 for "not found" and prints nothing. Any other
    // failure (no Secret Service on the bus, locked collection) is reported
    // with a fixed message so stderr is never relayed.
    if (result.code === 0) return result.stdout.length > 0 ? result.stdout : null;
    if (result.code === 1 && result.stdout.length === 0) return null;
    throw new Error("Secret Service call failed. Is a keyring daemon (GNOME Keyring, KWallet) running and unlocked?");
  }

  public async getMany(credentialIds: readonly string[]): Promise<Map<string, string>> {
    const out = new Map<string, string>();
    for (const id of credentialIds) {
      const value = await this.lookup(id);
      if (value !== null) out.set(id, value);
    }
    return out;
  }

  public async set(credentialId: string, value: string, comment = ""): Promise<void> {
    checkValue(value);
    // store reads the secret from stdin. The same attributes replace the
    // existing item, so the label (which carries the comment) stays current.
    const label = linuxLabel(assertId(credentialId), comment.slice(0, MAX_COMMENT));
    const result = await this.tool(["store", `--label=${label}`, "service", LINUX_SERVICE, "id", credentialId], value);
    if (result.code !== 0) throw new Error("Secret Service call failed. Is a keyring daemon (GNOME Keyring, KWallet) running and unlocked?");
  }

  public async delete(credentialId: string): Promise<boolean> {
    // clear exits 0 whether or not anything matched, so check first.
    if ((await this.lookup(credentialId)) === null) return false;
    const result = await this.tool(["clear", "service", LINUX_SERVICE, "id", credentialId]);
    if (result.code !== 0) throw new Error("Secret Service call failed.");
    return true;
  }

  public async list(): Promise<StoredKey[]> {
    // search prints attributes and labels. Only the id attribute and the
    // label are read; the output stays in this process.
    const result = await this.tool(["search", "--all", "service", LINUX_SERVICE]);
    if (result.code !== 0 && !(result.code === 1 && result.stdout.length === 0)) throw new Error("Secret Service call failed.");
    const out: StoredKey[] = [];
    for (const block of result.stdout.split(/^\[/mu)) {
      const id = /^attribute\.id = (.+)$/mu.exec(block)?.[1]?.trim();
      if (!id || !CREDENTIAL_ID_PATTERN.test(id)) continue;
      const label = /^label = (.*)$/mu.exec(block)?.[1] ?? "";
      const prefix = `${KEYCHAIN_PREFIX}${id}`;
      const comment = label.startsWith(`${prefix}: `) ? label.slice(prefix.length + 2) : "";
      out.push({ id, comment });
    }
    return out.sort((a, b) => a.id.localeCompare(b.id));
  }
}

// ---------------------------------------------------------------------------

/**
 * The platform keychain, or null where none is supported or it has been
 * switched off with BROKER_KEYCHAIN=off.
 */
export function platformSecretStore(
  env: Record<string, string | undefined> = process.env,
  platform: NodeJS.Platform = process.platform,
  runner: CommandRunner = execFileRunner,
): SecretStore | null {
  if (env.BROKER_KEYCHAIN?.toLowerCase() === "off") return null;
  if (platform === "win32") return new WindowsCredentialStore(runner);
  if (platform === "darwin") return new MacKeychainStore(runner);
  if (platform === "linux") return new LibSecretStore(runner);
  return null;
}
