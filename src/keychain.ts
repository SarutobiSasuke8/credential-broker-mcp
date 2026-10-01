import { execFile } from "node:child_process";

/**
 * OS keychain storage for credential secrets, so operators paste a key once
 * into a local form instead of editing environment variables or .env files.
 *
 * Windows only for now: secrets live in Windows Credential Manager as
 * generic credentials named `credential-broker/<credential-id>`, encrypted
 * by DPAPI under the operator's account and visible in Control Panel >
 * Credential Manager > Windows Credentials.
 *
 * This is a convenience store, not a boundary. Any process running as the
 * same OS user can read Credential Manager, exactly as it can read a .env
 * file. The secure-launch profile in SECURITY.md (dedicated OS user for the
 * broker) still applies; run the key manager as that user.
 */

export interface SecretStore {
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
 */
export const MAX_SECRET_BYTES = 2560;

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

function runPowerShell(request: object): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const child = execFile(
      "powershell.exe",
      ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", ENCODED_WINDOWS_SCRIPT],
      { windowsHide: true, maxBuffer: 4 * 1024 * 1024, timeout: 30_000 },
      (error, stdout) => {
        // stderr may echo the request on some failures, so it is never
        // relayed: callers get a fixed message.
        if (error) {
          reject(new Error("Windows Credential Manager call failed."));
          return;
        }
        try {
          resolve(JSON.parse(stdout) as Record<string, unknown>);
        } catch {
          reject(new Error("Windows Credential Manager returned unreadable output."));
        }
      },
    );
    child.stdin?.end(JSON.stringify(request), "utf8");
  });
}

const CREDENTIAL_ID_PATTERN = /^[a-z0-9][a-z0-9._-]{1,63}$/u;

function targetFor(credentialId: string): string {
  if (!CREDENTIAL_ID_PATTERN.test(credentialId)) throw new Error(`Invalid credential id '${credentialId}'.`);
  return `${KEYCHAIN_PREFIX}${credentialId}`;
}

export class WindowsCredentialStore implements SecretStore {
  public async getMany(credentialIds: readonly string[]): Promise<Map<string, string>> {
    const result = new Map<string, string>();
    if (credentialIds.length === 0) return result;
    const response = await runPowerShell({ op: "get", targets: credentialIds.map(targetFor) });
    const values = (response.values ?? {}) as Record<string, unknown>;
    for (const id of credentialIds) {
      const value = values[targetFor(id)];
      if (typeof value === "string" && value.length > 0) result.set(id, value);
    }
    return result;
  }

  public async set(credentialId: string, value: string, comment = ""): Promise<void> {
    if (value.length === 0) throw new Error("Refusing to store an empty secret.");
    if (Buffer.byteLength(value, "utf8") > MAX_SECRET_BYTES) {
      throw new Error(`Secret is longer than Credential Manager allows (${MAX_SECRET_BYTES} bytes).`);
    }
    // Credential Manager caps comments at 256 characters.
    await runPowerShell({ op: "set", target: targetFor(credentialId), value, comment: comment.slice(0, 250) });
  }

  public async delete(credentialId: string): Promise<boolean> {
    const response = await runPowerShell({ op: "delete", target: targetFor(credentialId) });
    return response.ok === true;
  }

  public async list(): Promise<StoredKey[]> {
    const response = await runPowerShell({ op: "list", filter: `${KEYCHAIN_PREFIX}*` });
    const targets = Array.isArray(response.targets) ? response.targets : [];
    return targets
      .filter((t): t is string => typeof t === "string" && t.startsWith(KEYCHAIN_PREFIX))
      .map((t) => {
        const [target = "", comment = ""] = t.split("\u0001");
        return { id: target.slice(KEYCHAIN_PREFIX.length), comment };
      });
  }
}

/**
 * The platform keychain, or null where none is supported or it has been
 * switched off with BROKER_KEYCHAIN=off.
 */
export function platformSecretStore(env: Record<string, string | undefined> = process.env): SecretStore | null {
  if (env.BROKER_KEYCHAIN?.toLowerCase() === "off") return null;
  if (process.platform === "win32") return new WindowsCredentialStore();
  return null;
}
