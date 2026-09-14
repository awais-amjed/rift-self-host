/**
 * Putting the server's endpoints where the edge runtime will find them.
 *
 * The runtime reads whatever is in its functions volume, and the console is
 * what fills that volume — from copies baked into its own image, so the set of
 * endpoints on a server is exactly the set that shipped with its console
 * version.
 *
 * The part that matters is that this **mirrors** rather than copies. Deleting
 * an endpoint has never removed it from a running stack: `cp -r` leaves the
 * old directory in place, so a function withdrawn in a release keeps answering
 * for as long as the volume survives. Everything not in the source is removed.
 */
import { join } from "jsr:@std/path@1";

/** What an install changed. */
export interface InstallReport {
  installed: string[];
  removed: string[];
}

/** Directories the runtime owns, which must survive a mirror. */
const PRESERVED = new Set<string>([]);

async function entryNames(directory: string): Promise<Set<string>> {
  const names = new Set<string>();
  try {
    for await (const entry of Deno.readDir(directory)) names.add(entry.name);
  } catch (error) {
    if (!(error instanceof Deno.errors.NotFound)) throw error;
  }
  return names;
}

/**
 * Copy every function from [sources] into [target], removing any that are no
 * longer present.
 *
 * [sources] is a list because the endpoints come from two places: the app
 * repo's own functions, and the runtime's `main` router, which is upstream
 * Supabase's and is not in the app repo at all.
 */
export async function installFunctions(
  sources: string[],
  target: string,
): Promise<InstallReport> {
  await Deno.mkdir(target, { recursive: true });

  const installed: string[] = [];
  for (const source of sources) {
    for (const name of await entryNames(source)) {
      const destination = join(target, name);
      await Deno.remove(destination, { recursive: true }).catch(() => {});
      await copyTree(join(source, name), destination);
      installed.push(name);
    }
  }

  const wanted = new Set([...installed, ...PRESERVED]);
  const removed: string[] = [];
  for (const name of await entryNames(target)) {
    if (wanted.has(name)) continue;
    await Deno.remove(join(target, name), { recursive: true });
    removed.push(name);
  }

  installed.sort();
  removed.sort();
  return { installed, removed };
}

/**
 * Where a server's endpoints come from: the app's own functions, and the edge
 * runtime's `main` router, which ships with the console's templates.
 */
export function functionSources(
  paths: { functionsDir: string; templateRoot: string },
): string[] {
  return [paths.functionsDir, join(paths.templateRoot, "functions-main")];
}

/**
 * The functions [sources] would install that [target] does not have.
 *
 * Asked on every start, because a server brought back from a backup has an
 * empty functions volume and nothing else noticed: the release recorded in the
 * restored database matches the image, so there was no upgrade to apply, and
 * every endpoint — `login` included — answered "could not find an appropriate
 * entrypoint". Found by restoring a real backup the way the docs said.
 *
 * By name only. An endpoint that is present but out of date is an upgrade's
 * business, and upgrades compare releases rather than directories.
 */
export async function missingFunctions(
  sources: string[],
  target: string,
): Promise<string[]> {
  const present = await entryNames(target);
  const missing: string[] = [];
  for (const source of sources) {
    for (const name of await entryNames(source)) {
      if (!present.has(name)) missing.push(name);
    }
  }
  return missing.sort();
}

/** Recursive copy. `Deno.copyFile` does not do directories. */
async function copyTree(from: string, to: string): Promise<void> {
  const info = await Deno.stat(from);
  if (!info.isDirectory) {
    await Deno.copyFile(from, to);
    return;
  }

  await Deno.mkdir(to, { recursive: true });
  for await (const entry of Deno.readDir(from)) {
    await copyTree(join(from, entry.name), join(to, entry.name));
  }
}
