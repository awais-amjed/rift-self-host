/**
 * Which releases are newer than this console, and what each one says.
 *
 * Read from the repository's GitHub releases, which the release workflow
 * writes from each tag's message, so the notes an operator reads before
 * updating are the ones written when the release was made. A failed check is
 * an answer of its own: a server with no way out to GitHub can still update
 * by naming a version (`update 1.0.14`).
 */

/** Where the releases are published. */
export const REPOSITORY = "awais-amjed/rift-self-host";

/** The console image, without a tag. Every release is pushed under its version. */
export const CONSOLE_IMAGE = "ghcr.io/awais-amjed/rift-console";

/** One published release. */
export interface Release {
  version: string;
  notes: string;
  url: string;
  prerelease: boolean;
}

/** `1.2.3` or `1.2.3-beta.4`, split into what is compared. */
function parse(version: string): { core: number[]; pre: string[] } | null {
  const match = /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.]+))?$/.exec(version.trim());
  if (!match) return null;
  return {
    core: [Number(match[1]), Number(match[2]), Number(match[3])],
    pre: match[4] ? match[4].split(".") : [],
  };
}

/** Whether [version] is one `scripts/release.sh` would make. */
export function isVersion(version: string): boolean {
  return parse(version) !== null;
}

/**
 * Negative when [a] is older than [b], positive when newer, zero when the
 * same — semver's order, so `1.1.0-beta.2` comes after `1.1.0-beta.1` and
 * before `1.1.0`. A string that is not a version sorts before every version.
 */
export function compareVersions(a: string, b: string): number {
  const left = parse(a);
  const right = parse(b);
  if (left === null || right === null) {
    return (left === null ? 0 : 1) - (right === null ? 0 : 1);
  }
  for (let i = 0; i < 3; i++) {
    if (left.core[i] !== right.core[i]) return left.core[i] - right.core[i];
  }
  // A release outranks any of its own pre-releases.
  if (left.pre.length === 0 || right.pre.length === 0) {
    return right.pre.length - left.pre.length;
  }
  for (let i = 0; i < Math.min(left.pre.length, right.pre.length); i++) {
    const x = left.pre[i];
    const y = right.pre[i];
    if (x === y) continue;
    const xn = /^\d+$/.test(x);
    const yn = /^\d+$/.test(y);
    if (xn && yn) return Number(x) - Number(y);
    if (xn !== yn) return xn ? -1 : 1;
    return x < y ? -1 : 1;
  }
  return left.pre.length - right.pre.length;
}

/**
 * The releases after [current], newest first.
 *
 * Pre-releases only for a console that is running one: somebody who chose a
 * beta is following betas, and nobody else should be offered one.
 */
export function newerReleases(releases: Release[], current: string): Release[] {
  const followingBetas = (parse(current)?.pre.length ?? 0) > 0;
  return releases
    .filter((release) => compareVersions(release.version, current) > 0)
    .filter((release) => followingBetas || !release.prerelease)
    .sort((a, b) => compareVersions(b.version, a.version));
}

/** GitHub's answer, reduced to the releases worth knowing about. */
export function releasesFrom(body: unknown): Release[] {
  if (!Array.isArray(body)) return [];
  return body.flatMap((row) => {
    const version = String(row?.tag_name ?? "").replace(/^v/, "");
    if (row?.draft || !isVersion(version)) return [];
    return [{
      version,
      notes: String(row?.body ?? "").trim(),
      url: String(row?.html_url ?? ""),
      prerelease: Boolean(row?.prerelease),
    }];
  });
}

/** Every published release, newest first as GitHub lists them. */
export async function fetchReleases(): Promise<Release[]> {
  const response = await fetch(
    `https://api.github.com/repos/${REPOSITORY}/releases?per_page=30`,
    {
      headers: { Accept: "application/vnd.github+json" },
      signal: AbortSignal.timeout(15_000),
    },
  );
  if (!response.ok) {
    await response.body?.cancel();
    throw new Error(`GitHub answered ${response.status}.`);
  }
  return releasesFrom(await response.json());
}

/**
 * A remembered answer. GitHub allows sixty unauthenticated requests an hour
 * from one address, and the dashboard reloads its state every ten seconds.
 */
let cached: { at: number; releases: Release[] | null; problem: string | null } | null =
  null;

const FRESH_MS = 3_600_000;
const RETRY_MS = 300_000;

/** The releases, from at most one request an hour (five minutes after a failure). */
export async function knownReleases(): Promise<
  { releases: Release[]; problem: null } | { releases: null; problem: string }
> {
  const age = cached === null ? Infinity : Date.now() - cached.at;
  if (cached === null || age > (cached.releases === null ? RETRY_MS : FRESH_MS)) {
    try {
      cached = { at: Date.now(), releases: await fetchReleases(), problem: null };
    } catch (error) {
      const why = error instanceof Error ? error.message : String(error);
      cached = { at: Date.now(), releases: null, problem: why };
    }
  }
  return cached.releases === null
    ? { releases: null, problem: cached.problem ?? "unknown" }
    : { releases: cached.releases, problem: null };
}
