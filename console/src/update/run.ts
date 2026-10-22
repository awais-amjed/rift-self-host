/**
 * Updating a stack to a newer release, in one step.
 *
 * Before this an update was three commands, and the first was the one that got
 * skipped: fetch the new compose file, `docker compose pull`, `up -d`. The
 * compose file pins every upstream image and carries their settings, so a
 * console pulled without it arrived on the old file — old Postgres, old
 * LiveKit flags — and applied migrations written for the new ones.
 *
 * Now the compose file comes with the console that expects it, and the console
 * is named by version in it, so a bare `docker compose pull` changes nothing.
 * An update, from the dashboard or `docker compose exec console update`:
 *
 *   1. downloads the new release's console image, and reads the compose file
 *      and the list of published versions out of it;
 *   2. replaces `docker-compose.yml` with the new one — unless the operator
 *      has edited theirs, when it stops and writes the new one beside it;
 *   3. downloads every image the new file names, and puts the old file back
 *      if that fails, since nothing has changed yet;
 *   4. brings each service onto the new file, recreating only what changed;
 *   5. hands over to a short-lived container that recreates the console on
 *      its new image. That console then does what any new console does on
 *      start (boot.ts): new endpoints, migrations, gateway routes.
 *
 * Step 5 has to be another container's, because `docker compose` running in
 * this one dies with it. It is also why the update cannot report its own end:
 * the page and the terminal hear "restarting", and the new console's log has
 * the rest.
 */
import { join } from "jsr:@std/path@1";
import {
  checkComposeFile,
  composedConsoleImage,
  composeProblem,
  fileInImage,
  projectDir,
  pullImage,
  pullServices,
  recreateConsoleSoon,
  stackServices,
  updateServices,
} from "../docker.ts";
import { imageVersion } from "../state.ts";
import {
  COMPOSE_FILE,
  type ComposeState,
  composeState,
  IMAGE_COMPOSE,
  IMAGE_KNOWN,
  knownHashes,
  lineDiff,
  NEW_COMPOSE_FILE,
  readCompose,
  replaceCompose,
} from "./compose_file.ts";
import {
  compareVersions,
  CONSOLE_IMAGE,
  isVersion,
  knownReleases,
  newerReleases,
  type Release,
} from "./releases.ts";

/** What the dashboard and `update --check` show before anything is done. */
export interface UpdateStatus {
  /** The release this console is. */
  current: string;
  /** Releases after it, newest first. Null when they could not be read. */
  releases: Release[] | null;
  /** Why they could not, when they could not. */
  problem: string | null;
  /** How the compose file on disk stands against this console's own. */
  compose: ComposeState;
  /**
   * The console image the compose file names, when it is not one of ours: a
   * stack running a console somebody built is updated by whoever builds it.
   */
  foreignImage: string | null;
  /** What pressing Update would move to, or null when there is nothing to do. */
  target: string | null;
}

/** How an update ended, short of throwing. */
export type UpdateOutcome =
  /** Handed over: the console is being recreated on [version]. */
  | { kind: "restarting"; version: string; warning: string | null }
  /** Stopped before changing anything: the compose file has the operator's edits. */
  | { kind: "edited"; version: string; diff: string; newFile: string }
  /** Nothing to do. */
  | { kind: "current"; version: string };

/** One line of progress. */
export interface UpdateProgress {
  step: string;
  done: boolean;
}

/** What to update to, and how. */
export interface UpdateRequest {
  /** A version to move to. The newest release when absent. */
  version?: string;
  /**
   * Use the compose file as it is, which the operator has brought up to the
   * new release by hand. Only accepted when it names the new console.
   */
  keepCompose?: boolean;
}

/** True while an update is running in this process. */
let running = false;

export function updateRunning(): boolean {
  return running;
}

/** The image of release [version]. */
export function imageOf(version: string): string {
  return `${CONSOLE_IMAGE}:${version}`;
}

/**
 * The console image the compose file names, if it is not one of ours: a
 * locally built one, or one `RIFT_CONSOLE_IMAGE` in `.env` substitutes.
 */
export function foreignImage(named: string | null): string | null {
  if (named === null) return null;
  const tag = named.startsWith(`${CONSOLE_IMAGE}:`)
    ? named.slice(CONSOLE_IMAGE.length + 1)
    : null;
  return tag !== null && (tag === "latest" || isVersion(tag)) ? null : named;
}

/**
 * Where an update would go: the newest release after this console, or this
 * console's own when only the compose file is behind — a stack whose console
 * arrived by a bare `docker compose pull` of `latest`, before the compose file
 * named one by version.
 */
export function updateTarget(
  current: string,
  newer: Release[] | null,
  compose: ComposeState,
): string | null {
  if (newer !== null && newer.length > 0) return newer[0].version;
  return compose === "release" ? current : null;
}

/** What is installed and what is available. */
export async function updateStatus(): Promise<UpdateStatus> {
  const current = imageVersion();
  const [found, own, known, onDisk, named] = await Promise.all([
    knownReleases(),
    Deno.readTextFile(IMAGE_COMPOSE).catch(() => null),
    Deno.readTextFile(IMAGE_KNOWN).catch(() => ""),
    readCompose(projectDir()),
    composedConsoleImage(),
  ]);
  const compose = own === null
    ? "edited"
    : await composeState(onDisk, own, knownHashes(known));
  const releases = found.releases === null
    ? null
    : newerReleases(found.releases, current);
  const foreign = foreignImage(named);
  return {
    current,
    releases,
    problem: found.problem,
    compose,
    foreignImage: foreign,
    target: foreign === null ? updateTarget(current, releases, compose) : null,
  };
}

/**
 * Update this stack, reporting each step.
 *
 * Throws, having changed nothing, when it cannot start. Once the compose file
 * is replaced it carries on to the handover rather than stopping half-way:
 * the old console on the new file is the state this exists to prevent.
 */
export async function runUpdate(
  request: UpdateRequest,
  report: (progress: UpdateProgress) => void = () => {},
): Promise<UpdateOutcome> {
  if (running) throw new Error("An update is already running.");
  running = true;
  try {
    return await update(request, report);
  } finally {
    running = false;
  }
}

async function update(
  request: UpdateRequest,
  report: (progress: UpdateProgress) => void,
): Promise<UpdateOutcome> {
  const step = async <T>(name: string, work: () => Promise<T>): Promise<T> => {
    report({ step: name, done: false });
    const value = await work();
    report({ step: name, done: true });
    return value;
  };

  const dir = projectDir();
  const current = imageVersion();
  const foreign = foreignImage(await composedConsoleImage());
  if (foreign !== null) {
    throw new Error(
      `This stack runs a console image of its own (${foreign}), so it is updated ` +
        "by whoever builds that image. Remove RIFT_CONSOLE_IMAGE from .env to " +
        "follow the published releases.",
    );
  }

  const version = request.version ?? await newestOrOwn(current, dir);
  if (version === null) return { kind: "current", version: current };
  if (!isVersion(version)) throw new Error(`${version} is not a version.`);
  if (compareVersions(version, current) < 0) {
    throw new Error(
      `This console is ${current}, newer than ${version}. A release cannot be taken ` +
        "back: the database has changes the older one does not know.",
    );
  }

  const image = imageOf(version);
  const { compose, known } = await step(`Downloading release ${version}`, async () => {
    if (version !== current) {
      const pulled = await pullImage(image);
      if (!pulled.ok) {
        throw new Error(`Could not download ${image}: ${composeProblem(pulled.stderr)}`);
      }
    }
    const read = (path: string) =>
      version === current
        ? Deno.readTextFile(path).catch(() => null)
        : fileInImage(image, path);
    const [compose, known] = await Promise.all([read(IMAGE_COMPOSE), read(IMAGE_KNOWN)]);
    if (compose === null) {
      throw new Error(
        `Release ${version} carries no compose file, so it cannot be updated to ` +
          "from here. Follow the updating guide for it.",
      );
    }
    return { compose, known: knownHashes(known ?? "") };
  });

  const previous = await readCompose(dir);
  const state = await composeState(previous, compose, known);
  if (state === "missing") {
    throw new Error(`There is no ${COMPOSE_FILE} in ${dir}.`);
  }
  if (state === "edited" && !request.keepCompose) {
    await Deno.writeTextFile(join(dir, NEW_COMPOSE_FILE), compose);
    return {
      kind: "edited",
      version,
      diff: lineDiff(previous!, compose),
      newFile: join(dir, NEW_COMPOSE_FILE),
    };
  }
  if (state === "current" && version === current) {
    return { kind: "current", version };
  }

  if (state === "edited") {
    // Their own file, which they say is up to date: it has to name the new
    // console, or the handover would bring back the old one.
    const named = await composedConsoleImage();
    if (named !== image) {
      throw new Error(
        `${COMPOSE_FILE} names the console ${named ?? "(unreadable)"}, not ${image}. ` +
          `Bring the changes from ${NEW_COMPOSE_FILE} into it first.`,
      );
    }
  } else if (state === "release") {
    await step("Writing the new compose file", async () => {
      const staged = join(dir, `.${COMPOSE_FILE}.check`);
      await Deno.writeTextFile(staged, compose);
      try {
        const checked = await checkComposeFile(staged);
        if (!checked.ok) {
          throw new Error(
            `Compose cannot read the new file: ${composeProblem(checked.stderr)}`,
          );
        }
      } finally {
        await Deno.remove(staged).catch(() => {});
      }
      await replaceCompose(dir, compose);
    });
  }

  const services = await stackServices();
  await step("Downloading the new images", async () => {
    const pulled = await pullServices(services);
    if (!pulled.ok) {
      // Nothing is running on the new file yet, so going back is clean.
      if (state === "release") await replaceCompose(dir, previous!);
      throw new Error(
        `Could not download the new images, so nothing was changed: ` +
          composeProblem(pulled.stderr),
      );
    }
  });

  const started = await step(
    "Starting the updated services",
    () => updateServices(services),
  );
  const warning = started.ok ? null : composeProblem(started.stderr);

  await step("Restarting the console", async () => {
    if (!await recreateConsoleSoon(image, "rift-console-update")) {
      throw new Error(
        `The new compose file is in place, but the console could not restart itself. ` +
          "Run `docker compose up -d` in the project folder to finish.",
      );
    }
  });

  return { kind: "restarting", version, warning };
}

/**
 * The newest release, or this console's own when only the compose file is
 * behind — which needs no list of releases, so a server that cannot reach
 * GitHub can still bring its file level.
 */
async function newestOrOwn(current: string, dir: string): Promise<string | null> {
  const found = await knownReleases();
  const own = await Deno.readTextFile(IMAGE_COMPOSE).catch(() => null);
  const known = knownHashes(await Deno.readTextFile(IMAGE_KNOWN).catch(() => ""));
  const compose = own === null
    ? "edited"
    : await composeState(await readCompose(dir), own, known);
  const newer = found.releases === null ? null : newerReleases(found.releases, current);
  const target = updateTarget(current, newer, compose);
  if (target === null && newer === null) {
    throw new Error(
      `Could not check for releases: ${found.problem}. To update to a release ` +
        "you name, run `docker compose exec console update <version>`.",
    );
  }
  return target;
}
