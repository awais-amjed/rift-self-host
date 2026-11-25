/**
 * One change to the stack at a time.
 *
 * Setup, a restore, the start-up's preparation, a key rotation, an update,
 * applying a release, a restart, the LAN switch, a file-limit change and a
 * backup each rewrite `.env` or the override, or recreate containers, or read
 * the database whole. Each used to keep its own flag, so two different ones
 * ran at once: an update pressed during a database rotation recreated the
 * console seconds after the rotation had changed the password and before it
 * had written it down, and the password was gone.
 *
 * The lock is a file in the project folder as well as a variable, because
 * `docker exec … console update` runs in a second process that the variable
 * cannot see. Its holder rewrites it every [BEAT_MS]; one not rewritten for
 * [STALE_MS] belongs to a process that died, and is taken over. (Asking
 * whether the process itself is alive would need `/proc`, which Deno opens
 * only to a process allowed everything.) The console also clears it as it
 * starts ([clearStaleLock]): whatever the container before held, it is gone.
 */
import { join } from "jsr:@std/path@1";

/** Thrown when something else is already changing the stack. */
export class OperationBusy extends Error {
  constructor(readonly running: string) {
    super(`The console is busy: ${running}. Try again when that has finished.`);
    this.name = "OperationBusy";
  }
}

const LOCK_FILE = ".console-operation.lock";

/** What this process holds, if anything. */
let held: string | null = null;

const BEAT_MS = 20_000;
const STALE_MS = 90_000;

function lockPath(projectDir: string): string {
  return join(projectDir, LOCK_FILE);
}

/** The operation another process holds the file for, or null. */
function heldElsewhere(projectDir: string, now = Date.now()): string | null {
  try {
    const { pid, name, beat } = JSON.parse(Deno.readTextFileSync(lockPath(projectDir)));
    if (pid === Deno.pid && held === null) return null;
    if (typeof beat !== "number" || now - beat > STALE_MS) return null;
    return String(name ?? "another change");
  } catch {
    return null;
  }
}

function lockBody(name: string): string {
  return JSON.stringify({ pid: Deno.pid, name, beat: Date.now() });
}

/** What is changing the stack right now, in this process or another, or null. */
export function currentOperation(projectDir: string): string | null {
  return held ?? heldElsewhere(projectDir);
}

function takeFile(projectDir: string, name: string): void {
  const path = lockPath(projectDir);
  const body = lockBody(name);
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      Deno.writeTextFileSync(path, body, { createNew: true, mode: 0o600 });
      return;
    } catch (error) {
      if (!(error instanceof Deno.errors.AlreadyExists)) {
        // A folder the console cannot write is reported by whatever it does
        // next; the lock is not worth failing over.
        return;
      }
      const other = heldElsewhere(projectDir);
      if (other !== null) throw new OperationBusy(other);
      // Stale: its holder stopped rewriting it.
      try {
        Deno.removeSync(path);
      } catch {
        // Taken by someone else meanwhile; the next attempt says so.
      }
    }
  }
  const other = heldElsewhere(projectDir);
  if (other !== null) throw new OperationBusy(other);
}

function dropFile(projectDir: string): void {
  try {
    const { pid } = JSON.parse(Deno.readTextFileSync(lockPath(projectDir)));
    if (pid === Deno.pid) Deno.removeSync(lockPath(projectDir));
  } catch {
    // Already gone.
  }
}

/**
 * Take the lock for [name] now, or throw [OperationBusy]. Synchronous, so a
 * caller that answers at once (a backup started in the background) learns
 * before it answers. Returns the function that lets it go.
 */
export function acquire(projectDir: string, name: string): () => void {
  if (held !== null) throw new OperationBusy(held);
  takeFile(projectDir, name);
  held = name;
  const beat = setInterval(() => {
    try {
      Deno.writeTextFileSync(lockPath(projectDir), lockBody(name), { mode: 0o600 });
    } catch {
      // Gone with its folder; the next acquire writes it again.
    }
  }, BEAT_MS);
  // Never what keeps a CLI run alive.
  Deno.unrefTimer(beat);
  let released = false;
  return () => {
    if (released) return;
    released = true;
    clearInterval(beat);
    held = null;
    dropFile(projectDir);
  };
}

/** Run [work] holding the lock for [name]; throws [OperationBusy] if it is taken. */
export async function exclusively<T>(
  projectDir: string,
  name: string,
  work: () => Promise<T>,
): Promise<T> {
  const release = acquire(projectDir, name);
  try {
    return await work();
  } finally {
    release();
  }
}

/** At start-up only: whatever the last container held, it holds no longer. */
export function clearStaleLock(projectDir: string): void {
  try {
    Deno.removeSync(lockPath(projectDir));
  } catch {
    // None.
  }
}
