import { randomBytes } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";

/**
 * Hot reload without a restart. The key manager writes a small marker file
 * after every change it makes (policy, key, import). A running broker that has
 * opted in (BROKER_HOT_RELOAD=1) compares the marker before each request and,
 * when it changed, rebuilds its policy and secrets.
 *
 * - It only reacts to a marker written by whoever can write the policy
 *   directory: the same trust as the policy file itself.
 * - A reload that fails (bad policy, identity removed) keeps the previous
 *   working state and is recorded, instead of leaving the broker half loaded.
 * - The pause switch is separate and is always live; it never needs a reload.
 */

export function reloadMarkerPath(policyFile: string, override: string | undefined = process.env.BROKER_RELOAD_MARKER): string {
  return override ? resolve(override) : join(dirname(resolve(policyFile)), ".broker-reload");
}

/** Records that something changed. The random part guarantees a new value every time. */
export async function touchReloadMarker(file: string): Promise<void> {
  await mkdir(dirname(file), { recursive: true });
  await writeFile(file, `${new Date().toISOString()} ${randomBytes(6).toString("hex")}\n`, { encoding: "utf8", mode: 0o600 });
}

async function readMarker(file: string): Promise<string> {
  try {
    return await readFile(file, "utf8");
  } catch {
    return "";
  }
}

export interface ReloadWatcherOptions<T> {
  markerFile: string;
  /** Builds the next state. May throw; the previous state is then kept. */
  load(): Promise<T>;
  /** Called once per failed marker value, with an operator-readable message. */
  onFailure?(message: string): void | Promise<void>;
  /** Called after a successful reload. */
  onReload?(): void | Promise<void>;
}

export class ReloadWatcher<T> {
  private lastSeen: string | undefined;

  public constructor(private readonly options: ReloadWatcherOptions<T>) {}

  /** Call once at start-up, after the first successful load. */
  public async init(): Promise<void> {
    this.lastSeen = await readMarker(this.options.markerFile);
  }

  /** The next state when the marker changed and loaded cleanly, else null. */
  public async refresh(): Promise<T | null> {
    const current = await readMarker(this.options.markerFile);
    if (current === this.lastSeen) return null;
    this.lastSeen = current;
    try {
      const next = await this.options.load();
      await this.options.onReload?.();
      return next;
    } catch (error) {
      await this.options.onFailure?.(error instanceof Error ? error.message : "Reload failed.");
      return null;
    }
  }
}
