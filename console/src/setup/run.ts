/**
 * Setup, start to finish.
 *
 * Seven steps between "here is my domain" and "here is your invite link". They
 * are ordered by what each one needs rather than by what reads nicely, and two
 * of the orderings are load-bearing:
 *
 * - The config files are written **before** anything starts, because until
 *   `.env` exists `docker compose` cannot resolve the `full` profile at all.
 * - The realtime limits are raised **after** the stack is up, because Realtime
 *   creates its own tenant row on first boot and there is nothing to update
 *   until it has.
 *
 * Every step reports through [SetupProgress] so the page can show what is
 * happening. Pulling the images alone can take minutes on a small VPS, and a
 * blank screen for that long reads as a hang.
 */
import { setting, updateSetting } from "../env_file.ts";
import { type PostgresTarget, waitUntilReachable } from "../postgres.ts";
import { restartService, startStack } from "../docker.ts";
import { applyPlan, planMigrations } from "../migrations/runner.ts";
import { publicUrlFor, type StackConfig, writeConfigFiles } from "./config_files.ts";
import { envHasPassword, problemsWith } from "./options.ts";
import { functionSources, installFunctions } from "./functions.ts";
import { type ProvisionedServer, provisionServer } from "./provision.ts";
import { applyLimits } from "./realtime.ts";
import { installTopicRules } from "./topic_rules.ts";
import { generateSecrets, type StackSecrets } from "./secrets.ts";
import { APPLIED_VERSION, imageVersion, writeState } from "../state.ts";

/** One line of progress. */
export interface SetupProgress {
  step: string;
  detail?: string;
  done: boolean;
}

/** What setup was asked for — the operator's answers, whole. */
export type SetupRequest = StackConfig;

/** What it produced. */
export interface SetupResult {
  secrets: StackSecrets;
  server: ProvisionedServer;
}

/** Where the console's own files live inside its image. */
export interface Paths {
  templateRoot: string;
  migrationsDir: string;
  /** The vendored copy of the app repo's functions. */
  functionsDir: string;
  /** The shared volume the edge runtime reads. */
  functionsTarget: string;
  projectDir: string;
}

/** The image's layout. Overridable so tests do not need one. */
export function defaultPaths(): Paths {
  const projectDir = Deno.env.get("RIFT_PROJECT_DIR") ?? Deno.cwd();
  return {
    templateRoot: "/app/templates",
    migrationsDir: "/app/migrations",
    functionsDir: "/app/functions",
    functionsTarget: "/srv/functions",
    projectDir,
  };
}

/** How long to wait for Postgres to start accepting connections. */
const DATABASE_TIMEOUT_MS = 120_000;

async function waitForDatabase(target: PostgresTarget): Promise<void> {
  if (await waitUntilReachable(target, DATABASE_TIMEOUT_MS)) return;
  throw new Error("Postgres did not come up. `docker compose logs db` will say why.");
}

/**
 * Run the whole thing.
 *
 * Throws on the first failure rather than continuing: every step after the
 * first assumes the ones before it, so carrying on would replace one clear
 * error with several confusing ones.
 */
export async function runSetup(
  request: SetupRequest,
  target: PostgresTarget,
  paths: Paths = defaultPaths(),
  report: (progress: SetupProgress) => void = () => {},
): Promise<SetupResult> {
  const step = async <T>(name: string, work: () => Promise<T>): Promise<T> => {
    report({ step: name, done: false });
    const value = await work();
    report({ step: name, done: true });
    return value;
  };

  const problems = problemsWith(request);
  if (problems.length > 0) throw new Error(problems.join("\n"));

  const secrets = await generateSecrets();

  // An operator's own choice wins over a generated one, in that order of
  // preference: what they typed, then what a hand-written .env already said,
  // then a fresh random string. The middle case is what lets somebody deploy
  // from a script and still reach the console afterwards.
  const chosen = request.consolePassword.trim();
  if (chosen.length > 0) {
    secrets.consolePassword = chosen;
  } else if (envHasPassword(paths.projectDir)) {
    secrets.consolePassword = setting("CONSOLE_PASSWORD") ?? secrets.consolePassword;
  }

  const context = { ...request, secrets };

  await step("Writing configuration", async () => {
    await writeConfigFiles(context, paths);
  });

  await step("Installing server endpoints", async () => {
    const installed = await installFunctions(
      functionSources(paths),
      paths.functionsTarget,
    );
    report({
      step: "Installing server endpoints",
      detail: `${installed.installed.length} endpoints`,
      done: false,
    });
  });

  await step("Starting containers", async () => {
    // The images are pulled here on a first run, which is most of the wait.
    //
    // Caddy is left out where it cannot or should not run — see
    // [disabledServices], which reads that from the `.env` written above
    // rather than taking it as an argument, so a later restart makes the same
    // decision this one did.
    const result = await startStack(["full"]);
    if (!result.ok) {
      throw new Error(result.stderr || "docker compose could not start the stack");
    }
  });

  // The password only exists as of this run, so the target handed in cannot
  // have carried it.
  const database = { ...target, password: secrets.postgresPassword };
  await step("Waiting for the database", () => waitForDatabase(database));

  await step("Applying the schema", async () => {
    const plan = await planMigrations(database, paths.migrationsDir);
    const outcomes = await applyPlan(database, plan, {
      onProgress: (outcome) =>
        report({
          step: "Applying the schema",
          detail: outcome.migration.name,
          done: false,
        }),
    });
    const failure = outcomes.find((outcome) => !outcome.ok);
    if (failure) {
      throw new Error(`${failure.migration.name} failed:\n${failure.error}`);
    }
  });

  await step("Provisioning realtime", async () => {
    // By now the seed has created the tenant row on first boot. Turning the
    // seed off *before* raising the limits is what makes the raise stick: with
    // it on, the next restart deletes and reinserts the row at free-tier
    // defaults.
    await updateSetting("REALTIME_SEED", "false", paths.projectDir);

    const applied = await applyLimits(database);
    if (!applied) {
      throw new Error(
        "Realtime has not created its tenant yet. Its container may still be starting.",
      );
    }

    // Recreated rather than restarted, for two reasons that both bite: a
    // restart keeps the environment the container was made with, so it would
    // not see REALTIME_SEED change; and the tenant config is cached in the
    // running process, so the UPDATE alone changes nothing either way.
    await restartService("realtime");

    // Usually too early — Realtime makes the table these attach to when its
    // first client connects — in which case the console's watch installs them
    // the moment it exists. See topic_rules.ts.
    await installTopicRules(database);
  });

  const server = await step("Creating your server", () =>
    provisionServer({
      publicUrl: publicUrlFor(request),
      // Published directly when there is no proxy in front of it.
      livekitSignallingPort: request.localTesting ? 7880 : undefined,
      internalUrl: "http://kong:8000",
      // Matches what the functions container holds, which is now the
      // opaque secret key rather than the legacy JWT.
      serviceRoleKey: secrets.secretKey,
      serverName: request.serverName,
      livekitApiKey: secrets.livekitApiKey,
      livekitApiSecret: secrets.livekitApiSecret,
    }));

  // A stack that has just been built is at this release, and saying so is what
  // stops the first boot after setup offering to "upgrade" to what it already
  // is.
  await writeState(database, APPLIED_VERSION, imageVersion());

  return { secrets, server };
}
