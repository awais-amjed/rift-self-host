/**
 * Keeping the newest release where the server can tell its admins.
 *
 * The dashboard and `update` ask GitHub only when somebody looks, so a server
 * nobody looked at sat on an old console. This asks on its own, a few minutes
 * after the console starts and every six hours after, and keeps the answer in
 * `rift_console.state` under [UPDATE_AVAILABLE]. `get_server_details` hands it
 * to the server's admins (`app.console_update`, migration 029), and the app
 * says so under the server's name. Telling only: updating stays here.
 *
 * Kept as `{version, url, notes}` of the newest release this console would be
 * offered (`newerReleases`, so betas only for a console running one), and
 * cleared when there is none. A check that could not reach GitHub leaves what
 * is there: a server cut off from GitHub for a day has not been updated.
 * Recording a new version after an update clears it as well (`upgrade.ts`),
 * so the notice goes when the update lands rather than at the next check.
 */
import { targetFromEnv } from "../postgres.ts";
import { clearState, imageVersion, UPDATE_AVAILABLE, writeState } from "../state.ts";
import { knownReleases, newerReleases, type Release } from "./releases.ts";

/** How much of a release's notes is kept: they ride in every admin's server details. */
export const MAX_NOTES = 4000;

const FIRST_CHECK_MS = 5 * 60 * 1000;
const CHECK_MS = 6 * 60 * 60 * 1000;

export type Notice =
  | { kind: "set"; value: string }
  | { kind: "clear" }
  | { kind: "keep" };

/** What to keep for a console on [current], given GitHub's answer (null: none). */
export function noticeFor(releases: Release[] | null, current: string): Notice {
  if (releases === null) return { kind: "keep" };
  const newest = newerReleases(releases, current)[0];
  if (newest === undefined) return { kind: "clear" };
  return {
    kind: "set",
    value: JSON.stringify({
      version: newest.version,
      url: newest.url,
      notes: capped(newest.notes),
    }),
  };
}

/** [notes] whole, or cut at the last line break that fits, with an ellipsis after. */
function capped(notes: string): string {
  if (notes.length <= MAX_NOTES) return notes;
  const head = notes.slice(0, MAX_NOTES - 1);
  const lineEnd = head.lastIndexOf("\n");
  return `${lineEnd > 0 ? head.slice(0, lineEnd) : head}\n…`;
}

/** The last thing written, so the log says when the notice changes and not every check. */
let last: string | null | undefined;

/** Check now and then every six hours, from a few minutes after start, while [isReady]. */
export function startUpdateNotice(isReady: () => boolean): void {
  const check = () =>
    checkOnce(isReady).catch((error) => console.error("[update] release check:", error));
  setTimeout(() => {
    void check();
    setInterval(check, CHECK_MS);
  }, FIRST_CHECK_MS);
}

async function checkOnce(isReady: () => boolean): Promise<void> {
  if (!isReady()) return;
  const { releases } = await knownReleases();
  const notice = noticeFor(releases, imageVersion());
  if (notice.kind === "keep") return;
  const target = targetFromEnv();
  if (notice.kind === "clear") {
    if (last !== null) await clearState(target, UPDATE_AVAILABLE);
    last = null;
    return;
  }
  if (notice.value === last) return;
  await writeState(target, UPDATE_AVAILABLE, notice.value);
  last = notice.value;
  console.log(`[update] a newer release is out: ${JSON.parse(notice.value).version}`);
}
