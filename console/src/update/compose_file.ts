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
 * The lines that differ between [before] and [after], with [context] lines
 * around each change: `-` for a line only in [before], `+` for one only in
 * [after], and `@@` with the line number in [after] where a stretch begins.
 *
 * Its own small function because the image has no `diff` the console may run,
 * and a compose file is a few hundred lines: a table of common subsequences is
 * instant at that size.
 */
export function lineDiff(before: string, after: string, context = 3): string {
  // Split into lines, without the empty one after a file's last newline.
  const lines = (text: string) => text.replace(/\n$/, "").split("\n");
  const a = lines(before);
  const b = lines(after);
  const n = a.length;
  const m = b.length;

  // common[i][j]: the longest common subsequence of a[i..] and b[j..].
  const common = new Uint32Array((n + 1) * (m + 1));
  const at = (i: number, j: number) => i * (m + 1) + j;
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      common[at(i, j)] = a[i] === b[j]
        ? common[at(i + 1, j + 1)] + 1
        : Math.max(common[at(i + 1, j)], common[at(i, j + 1)]);
    }
  }

  const steps: { mark: " " | "-" | "+"; text: string; after: number }[] = [];
  let i = 0;
  let j = 0;
  while (i < n || j < m) {
    if (i < n && j < m && a[i] === b[j]) {
      steps.push({ mark: " ", text: a[i], after: j });
      i++;
      j++;
    } else if (i < n && (j === m || common[at(i + 1, j)] >= common[at(i, j + 1)])) {
      // What went comes before what replaced it, as in any diff.
      steps.push({ mark: "-", text: a[i], after: j });
      i++;
    } else {
      steps.push({ mark: "+", text: b[j], after: j });
      j++;
    }
  }

  const shown = new Set<number>();
  steps.forEach((line, index) => {
    if (line.mark === " ") return;
    for (let k = index - context; k <= index + context; k++) shown.add(k);
  });

  const out: string[] = [];
  let previous = -2;
  steps.forEach((line, index) => {
    if (!shown.has(index)) return;
    if (index !== previous + 1) out.push(`@@ line ${line.after + 1}`);
    out.push(`${line.mark} ${line.text}`);
    previous = index;
  });
  return out.join("\n");
}
