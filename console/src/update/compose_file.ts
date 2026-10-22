/**
 * The compose file an update replaces, and how the console knows it may.
 *
 * Each console image carries its release's `docker-compose.yml`, and a list
 * of the hash of every version of that file ever published
 * (`known-compose.sha256`, kept by `scripts/known_compose.sh`). A file on disk
 * whose hash is on the list is one the operator downloaded and never touched,
 * so replacing it loses nothing. One that is not has changes of their own: the
 * new file is written beside it instead, with the difference shown, and the
 * operator decides.
 *
 * A list rather than a hash recorded when the console last wrote the file,
 * because most files were never written by a console at all: they were
 * fetched with curl, from whichever release was current that day.
 */
import { encodeHex } from "jsr:@std/encoding@1/hex";
import { join } from "jsr:@std/path@1";
import { changedLines, lineDiff, merge3, splitLines } from "./line_merge.ts";

/** The file compose finds without being told, and the one an update replaces. */
export const COMPOSE_FILE = "docker-compose.yml";

/** Where the new file goes when the old one has changes of the operator's. */
export const NEW_COMPOSE_FILE = "docker-compose.yml.new";

/** Where an image keeps its release's compose file, and the list. */
export const IMAGE_COMPOSE = "/app/docker-compose.yml";
export const IMAGE_KNOWN = "/app/known-compose.sha256";

/**
 * How the file on disk relates to a release's:
 *
 * - `current`: it is that release's file.
 * - `release`: it is some other published version, never edited — safe to
 *   replace.
 * - `edited`: it is not any published version.
 * - `missing`: there is no file.
 */
export type ComposeState = "current" | "release" | "edited" | "missing";

export async function sha256(text: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return encodeHex(new Uint8Array(digest));
}

/** The hashes in a `known-compose.sha256`: one per line, `#` for comments. */
export function knownHashes(text: string): Set<string> {
  return new Set(
    text.split("\n")
      .map((line) => line.trim().split(/\s+/)[0])
      .filter((hash) => /^[0-9a-f]{64}$/.test(hash)),
  );
}

/** Where [onDisk] stands against a release's [wanted] file and the [known] hashes. */
export async function composeState(
  onDisk: string | null,
  wanted: string,
  known: Set<string>,
): Promise<ComposeState> {
  if (onDisk === null) return "missing";
  if (onDisk === wanted) return "current";
  return known.has(await sha256(onDisk)) ? "release" : "edited";
}

/** The compose file in [projectDir], or null. */
export function readCompose(projectDir: string): Promise<string | null> {
  return Deno.readTextFile(join(projectDir, COMPOSE_FILE)).catch(() => null);
}

/**
 * Put [text] in place of [projectDir]'s compose file in one step: written
 * beside it, then renamed over it, so compose never reads half a file.
 */
export async function replaceCompose(projectDir: string, text: string): Promise<void> {
  const staged = join(projectDir, `.${COMPOSE_FILE}.update`);
  await Deno.writeTextFile(staged, text);
  await Deno.rename(staged, join(projectDir, COMPOSE_FILE));
}

/**
 * Every published version of the compose file, which this image carries so
 * that an edited file can be merged: named by hash, written by
 * `scripts/known_compose.sh`.
 */
export const IMAGE_PUBLISHED = "/app/known-compose";

/** The published versions in [directory], or none when there is no folder. */
export async function publishedVersions(directory = IMAGE_PUBLISHED): Promise<string[]> {
  const versions: string[] = [];
  try {
    for await (const entry of Deno.readDir(directory)) {
      if (entry.isFile && entry.name.endsWith(".yml")) {
        versions.push(await Deno.readTextFile(join(directory, entry.name)));
      }
    }
  } catch (error) {
    if (!(error instanceof Deno.errors.NotFound)) throw error;
  }
  return versions;
}

/**
 * What an update can do with a file of the operator's own:
 *
 * - `clean`: their changes and the release's merge, into [text]; [diff] is
 *   what that changes in their file.
 * - `conflict`: both changed the same lines, at [lines] in their file.
 * - `unknown`: no published version is near enough to be where theirs began.
 */
export type ComposeMerge =
  | { kind: "clean"; text: string; diff: string }
  | { kind: "conflict"; lines: number[] }
  | { kind: "unknown" };

/**
 * Merge [onDisk] with a release's [wanted] file, starting from the published
 * version [onDisk] is closest to — the one it was downloaded as, unless it
 * was edited past recognition, when more than a third of it differs from
 * every version and nothing is guessed.
 */
export function mergeCompose(
  onDisk: string,
  wanted: string,
  published: string[],
): ComposeMerge {
  let base: string | null = null;
  let fewest = Infinity;
  for (const version of published) {
    const changed = changedLines(version, onDisk);
    if (changed < fewest) {
      base = version;
      fewest = changed;
    }
  }
  if (base === null || fewest > splitLines(onDisk).length / 3) return { kind: "unknown" };
  const merged = merge3(base, onDisk, wanted);
  return merged.clean
    ? { kind: "clean", text: merged.text, diff: lineDiff(onDisk, merged.text) }
    : { kind: "conflict", lines: merged.conflicts };
}

/**
 * Keep the operator's file as `docker-compose.yml.before-<version>` before an
 * update writes over it: theirs, so it is never simply lost. Returns the name.
 */
export async function setAside(projectDir: string, version: string): Promise<string> {
  for (let n = 1;; n++) {
    const name = `${COMPOSE_FILE}.before-${version}${n === 1 ? "" : `-${n}`}`;
    // Another try at the same update: the copy from the first is kept too.
    if (await Deno.lstat(join(projectDir, name)).then(() => true, () => false)) continue;
    await Deno.copyFile(join(projectDir, COMPOSE_FILE), join(projectDir, name));
    return name;
  }
}
