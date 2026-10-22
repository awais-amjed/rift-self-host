/**
 * `docker compose exec console update`: the dashboard's Update, from a
 * terminal.
 *
 *   update                  the newest release, after showing its notes
 *   update 1.0.14           that release, without asking GitHub
 *   update --check          what is available, changing nothing
 *   update --yes            no question before starting
 *   update --keep-compose   use docker-compose.yml as it is, once you have
 *                           brought your own edits up to the new release
 *
 * Runs in its own process beside the console, which it replaces at the end —
 * so the terminal's last line is the handover, and the new console's log
 * (`docker compose logs -f console`) has the rest.
 */
import { parseArgs } from "jsr:@std/cli@1/parse-args";
import { isConfigured } from "../web/stack_state.ts";
import { NEW_COMPOSE_FILE } from "./compose_file.ts";
import { runUpdate, updateStatus } from "./run.ts";

const COMMAND = "docker compose exec console update";

function notesOf(status: Awaited<ReturnType<typeof updateStatus>>): string {
  return (status.releases ?? []).map((release) =>
    `── ${release.version} ${"─".repeat(Math.max(0, 50 - release.version.length))}\n` +
    (release.notes || "(no notes)")
  ).join("\n\n");
}

async function main(): Promise<number> {
  const args = parseArgs(Deno.args, {
    boolean: ["check", "yes", "keep-compose", "help"],
    alias: { y: "yes", h: "help" },
  });
  if (args.help) {
    console.log(`Usage: ${COMMAND} [version] [--check] [--yes] [--keep-compose]`);
    return 0;
  }
  if (!isConfigured()) {
    console.error("This stack has not finished setup, so there is nothing to update.");
    return 1;
  }
  const version = args._.length > 0 ? String(args._[0]) : undefined;

  if (version === undefined) {
    const status = await updateStatus();
    console.log(`This console: ${status.current}`);
    if (status.foreignImage !== null) {
      console.log(`It runs its own image (${status.foreignImage}); nothing to check.`);
      return 0;
    }
    if (status.releases === null) {
      console.log(`Could not check for releases: ${status.problem}`);
      if (status.target === null) {
        console.error(`Name one to update to it: ${COMMAND} <version>`);
        return 1;
      }
    } else if (status.releases.length > 0) {
      console.log(`\n${notesOf(status)}\n`);
    }
    if (status.target === null) {
      console.log(
        status.compose === "edited"
          ? "Up to date. (docker-compose.yml has changes of your own.)"
          : "Up to date.",
      );
      return 0;
    }
    console.log(
      status.target === status.current
        ? `docker-compose.yml is from an older release; ${status.current} brings it up to date.`
        : `Newest release: ${status.target}`,
    );
  }
  if (args.check) return 0;

  if (!args.yes) {
    if (!Deno.stdin.isTerminal()) {
      console.error("Add --yes to update without being asked.");
      return 1;
    }
    console.log(
      "\nMake a backup first (the console's Backups tab). The server stops answering\n" +
        "for a minute or two while services restart; apps reconnect by themselves.",
    );
    if (!confirm("Update now?")) return 1;
  }

  const outcome = await runUpdate(
    { version, keepCompose: args["keep-compose"] },
    (progress) => {
      if (!progress.done) console.log(`→ ${progress.step}`);
    },
  );

  switch (outcome.kind) {
    case "current":
      console.log(`Already on ${outcome.version}.`);
      return 0;
    case "edited":
      console.log(`
docker-compose.yml has changes of your own, so it was left as it is and nothing
was updated. Release ${outcome.version}'s file is ${outcome.newFile}.
What differs, from yours (-) to the new one (+):

${outcome.diff}

Either use the new file, putting back what you need from yours afterwards:

  mv ${NEW_COMPOSE_FILE} docker-compose.yml && ${COMMAND} ${outcome.version}

or bring the new release's changes into your file, then:

  ${COMMAND} ${outcome.version} --keep-compose
`);
      return 2;
    case "restarting":
      if (outcome.warning) {
        console.log(`Not every service started cleanly: ${outcome.warning}`);
      }
      console.log(`
The console is restarting on ${outcome.version}; it finishes the update itself
(endpoints, database changes). Follow it with:

  docker compose logs -f console
`);
      return 0;
  }
}

if (import.meta.main) {
  try {
    Deno.exit(await main());
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    Deno.exit(1);
  }
}
