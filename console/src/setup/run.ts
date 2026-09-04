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
import { join } from "jsr:@std/path@1";
import { isReachable, type PostgresTarget } from "../postgres.ts";
import { restartService, startStack } from "../docker.ts";
import { applyPlan, planMigrations } from "../migrations/runner.ts";
import { type StackConfig, writeConfigFiles } from "./config_files.ts";
import { installFunctions } from "./functions.ts";
import { type ProvisionedServer, provisionServer } from "./provision.ts";
import { applyLimits } from "./realtime.ts";
import { generateSecrets, type StackSecrets } from "./secrets.ts";

/** One line of progress. */
export interface SetupProgress {
  step: string;
  detail?: string;
  done: boolean;
}

/** What setup was asked for. */
export interface SetupRequest extends StackConfig {
  serverName: string;
}

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
  const deadline = Date.now() + DATABASE_TIMEOUT_MS;
  while (Date.now() < deadline) {
    if (await isReachable(target)) return;
    await new Promise((resolve) => setTimeout(resolve, 2000));
  }
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

  const secrets = await generateSecrets();
  const context = { ...request, secrets };

  await step("Writing configuration", async () => {
    await writeConfigFiles(context, paths);
  });

  await step("Installing server endpoints", async () => {
    const installed = await installFunctions(
      [paths.functionsDir, join(paths.templateRoot, "functions-main")],
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
    const applied = await applyLimits(database);
    if (!applied) {
      throw new Error(
        "Realtime has not created its tenant yet. Its container may still be starting.",
      );
    }
    // Recreated rather than restarted: a restart keeps the environment the
    // container was made with, and the tenant config is cached in the running
    // process regardless, so the UPDATE alone changes nothing.
    await restartService("realtime");
  });

  const server = await step("Creating your server", () =>
    provisionServer({
      publicUrl: `https://${request.domain}`,
      internalUrl: "http://kong:8000",
      serviceRoleKey: secrets.serviceRoleKey,
      serverName: request.serverName,
      livekitApiKey: secrets.livekitApiKey,
      livekitApiSecret: secrets.livekitApiSecret,
    }));

  return { secrets, server };
}
