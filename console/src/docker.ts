/**
 * Driving the rest of the stack.
 *
 * The console runs `docker compose` as a subprocess rather than speaking to
 * the Engine API directly. The compose file is already the description of what
 * should be running, and reimplementing its dependency ordering, healthchecks
 * and profile handling against the raw API would be a second, worse copy of
 * it that drifts.
 *
 * This works because the container mounts the Docker socket and the project
 * directory at the path it has on the host — see the console service in
 * docker-compose.yml for why that path has to match.
 */
import { run, runFromFile, runToFile } from "./subprocess.ts";
import { setting } from "./env_file.ts";

/** One service, as compose sees it. */
export interface ServiceStatus {
  name: string;
  /** created | running | restarting | exited | paused | dead */
  state: string;
  /** healthy | unhealthy | starting, or "" where no healthcheck is defined. */
  health: string;
  /** What compose prints as the status, e.g. "Up 4 minutes (healthy)". */
  status: string;
  /** The image the container was made from, as named: `kong/kong:3.9.1`. */
  image: string;
}

/** The result of running a compose command. */
export interface CommandResult {
  ok: boolean;
  stdout: string;
  stderr: string;
}

/** Where the project lives, both here and on the host. */
export function projectDir(): string {
  return Deno.env.get("RIFT_PROJECT_DIR") ?? Deno.cwd();
}

async function compose(
  args: string[],
  timeoutMs = 600_000,
  stdin?: string,
): Promise<CommandResult> {
  const result = await run("docker", ["compose", ...args], {
    cwd: projectDir(),
    timeoutMs,
    stdin,
  });
  return { ok: result.code === 0, stdout: result.stdout, stderr: result.stderr };
}

/**
 * Run [command] inside the running [service] container, with [stdin] piped in.
 *
 * `-T` because there is no terminal here, and a TTY allocated over a pipe
 * mangles whatever the command writes to stdout.
 */
export function execInService(
  service: string,
  command: string[],
  stdin?: string,
  timeoutMs = 120_000,
): Promise<CommandResult> {
  return compose(
    ["--profile", "full", "exec", "-T", service, ...command],
    timeoutMs,
    stdin,
  );
}

/** [command] inside [service], with its output written to [path] on this side. */
export function execToFile(
  service: string,
  command: string[],
  path: string,
): Promise<{ code: number; stderr: string }> {
  return runToFile("docker", [
    "compose",
    "--profile",
    "full",
    "exec",
    "-T",
    service,
    ...command,
  ], {
    cwd: projectDir(),
    path,
  });
}

/** [command] inside [service], reading [path] from this side as its input. */
export function execFromFile(
  service: string,
  command: string[],
  path: string,
): Promise<{ code: number; stderr: string }> {
  return runFromFile("docker", [
    "compose",
    "--profile",
    "full",
    "exec",
    "-T",
    service,
    ...command,
  ], {
    cwd: projectDir(),
    path,
  });
}

/**
 * Restart every service this stack runs, except the console doing the asking.
 *
 * `restart` rather than `up`: nothing about the configuration changed, and
 * `restart` never creates a container this stack does not run — Caddy, beside
 * somebody else's proxy.
 */
export async function restartStackServices(): Promise<CommandResult> {
  const skip = new Set([SELF, ...disabledServices()]);
  const services = (await servicesIn(["full"])).filter((service) => !skip.has(service));
  return compose(["--profile", "full", "restart", ...services], 300_000);
}

/**
 * What is running right now.
 *
 * Returns an empty list before setup, when the compose file has no `.env` to
 * resolve and nothing but the console exists.
 */
export async function serviceStatuses(): Promise<ServiceStatus[]> {
  const result = await compose(["ps", "--all", "--format", "json"], 30_000);
  if (!result.ok) return [];

  // One JSON object per line, not a JSON array — compose changed this once and
  // may again, so both shapes are accepted.
  const text = result.stdout;
  if (text.length === 0) return [];

  const rows: Record<string, string>[] = text.startsWith("[")
    ? JSON.parse(text)
    : text.split("\n").filter((line) => line.trim().length > 0).map((line) =>
      JSON.parse(line)
    );

  return rows.map((row) => ({
    name: row.Service ?? row.Name ?? "",
    state: row.State ?? "",
    health: row.Health ?? "",
    status: row.Status ?? "",
    image: row.Image ?? "",
  }));
}

/** The service the console runs as, which it must never bring up. */
const SELF = "console";

/** Where the console is published, and where `.env` wants it. */
export interface ConsoleAddress {
  bind: string;
  port: string;
}

/**
 * Whether the console has to move: only when Docker could say where it is
 * now, and that differs from what `.env` names.
 */
export function consoleMoveNeeded(
  published: ConsoleAddress | null,
  wanted: ConsoleAddress,
): boolean {
  return published !== null &&
    (published.bind !== wanted.bind || published.port !== wanted.port);
}

/** The console container's image and published address, from Docker. */
async function publishedConsole(): Promise<(ConsoleAddress & { image: string }) | null> {
  const result = await run("docker", [
    "inspect",
    "rift-console",
    "--format",
    "{{.Config.Image}}|{{json .HostConfig.PortBindings}}",
  ], { timeoutMs: 15_000 });
  if (result.code !== 0) return null;
  const [image, bindings] = result.stdout.split("|");
  try {
    const first = (JSON.parse(bindings)["8080/tcp"] ?? [])[0];
    if (!first) return null;
    return { image, bind: first.HostIp || "0.0.0.0", port: String(first.HostPort) };
  } catch {
    return null;
  }
}

/**
 * Recreate the console on the interface and port `.env` names, if it is not
 * already there. Returns where it is going, or null when it stays.
 *
 * Setup writes both settings, but the console was published by the
 * operator's own `docker compose up -d`, before they existed. It cannot
 * recreate itself — `docker compose` running inside it is killed with the old
 * container before the new one exists — so a short-lived container of the
 * same image does it, after a pause that lets the page hear the answer first.
 */
export async function moveConsoleIfChanged(): Promise<ConsoleAddress | null> {
  const published = await publishedConsole();
  const wanted = {
    bind: setting("CONSOLE_BIND") ?? "127.0.0.1",
    port: setting("CONSOLE_PORT") ?? "8080",
  };
  if (published === null || !consoleMoveNeeded(published, wanted)) return null;

  const dir = projectDir();
  const started = await run("docker", [
    "run",
    "-d",
    "--rm",
    "--name",
    "rift-console-move",
    "-v",
    "/var/run/docker.sock:/var/run/docker.sock",
    "-v",
    `${dir}:${dir}`,
    "-w",
    dir,
    // The compose file mounts and works in ${PWD}.
    "-e",
    `PWD=${dir}`,
    "-e",
    "COMPOSE_PROJECT_NAME=rift",
    "--entrypoint",
    "sh",
    published.image,
    "-c",
    "sleep 5; docker compose up -d --no-deps --force-recreate console",
  ], { timeoutMs: 60_000 });
  if (started.code !== 0) {
    console.error("Could not move the console:", started.stderr);
    return null;
  }
  return wanted;
}

/**
 * Services this stack has been configured not to run.
 *
 * Read from `.env` rather than passed in, because the answer is a property of
 * the stack and every caller needs it. It used to be an argument that setup
 * passed and the dashboard's "Restart the stack" did not — so a local-testing
 * stack came back from a restart with Caddy running, failing ACME challenges
 * against a name that does not resolve.
 *
 * Caddy is the only one so far. It is left out when a certificate cannot be
 * issued (a LAN address) or is not wanted (the operator's own proxy already
 * terminates TLS on this machine).
 */
export function disabledServices(): string[] {
  const noCaddy = setting("RIFT_LOCAL_TESTING") === "true" ||
    setting("RIFT_OWN_PROXY") === "true";
  return noCaddy ? ["caddy"] : [];
}

/** Every service in [profiles], as the compose file defines them. */
export async function servicesIn(profiles: string[]): Promise<string[]> {
  const flags = profiles.flatMap((profile) => ["--profile", profile]);
  const result = await compose([...flags, "config", "--services"], 30_000);
  if (!result.ok) return [];
  return result.stdout.split("\n").map((line) => line.trim()).filter((line) =>
    line.length > 0
  );
}

/**
 * Bring up every service in [profiles] except this one, waiting for
 * healthchecks to pass.
 *
 * Anything in [disabledServices] is left out, and [options.exclude] adds to
 * that for a caller with a reason of its own.
 *
 * Excluding the console is not tidiness. A plain `up` covers every service in
 * the project, and the console *is* one of them — so it recreates the container it
 * is running in, SIGTERMs itself mid-setup, and the operator watches the
 * progress stream die at "Starting containers" with no error, because the
 * process that would have reported one is gone.
 *
 * The list is read back from the compose file rather than written down here,
 * so a service added later is started without anyone remembering to add it.
 */
export async function startStack(
  profiles: string[] = ["full"],
  options: { exclude?: string[] } = {},
): Promise<CommandResult> {
  const skip = new Set([SELF, ...disabledServices(), ...(options.exclude ?? [])]);
  const services = (await servicesIn(profiles)).filter((s) => !skip.has(s));
  if (services.length === 0) {
    return {
      ok: false,
      stdout: "",
      stderr: "Could not read the service list from the compose file.",
    };
  }

  // No --remove-orphans: it is scoped to services the compose file no longer
  // defines, but the blast radius if that ever changed is this container.
  return compose(upArgs(profiles, services));
}

/**
 * The compose arguments that bring [services] up without recreating anything.
 *
 * `--no-recreate` because compose's own judgement of "this container is out of
 * date" depends on the compose version that made it. It compares a config hash
 * and labels recording the image digest and the dependencies, and different
 * versions write those differently — so a container an operator started with
 * the host's compose looked changed to the console's, and the console's next
 * start recreated it, database included, and the reverse. The things that do
 * need a container recreated — a new image, a rotated key, the LAN switch —
 * each recreate exactly their own service instead.
 */
export function upArgs(profiles: string[], services: string[]): string[] {
  return [
    ...profiles.flatMap((profile) => ["--profile", profile]),
    "up",
    "-d",
    "--no-recreate",
    "--wait",
    ...services,
  ];
}

/**
 * Services whose container was made from a different image than the compose
 * file names now.
 *
 * Compared by the image *name*, `kong/kong:3.9.1`, which reads the same to
 * every compose version — unlike the digest compose records, which is what made
 * its own recreate decision unreliable across versions. The console's own
 * container is left out: replacing it is the operator's `docker compose up -d`.
 */
export function outdatedServices(
  wanted: Record<string, string>,
  running: ServiceStatus[],
): string[] {
  return running
    .filter((container) =>
      container.name !== SELF &&
      wanted[container.name] !== undefined &&
      container.image !== wanted[container.name]
    )
    .map((container) => container.name)
    .sort();
}

/** The image each service in [profiles] names, as the compose file says now. */
async function serviceImages(profiles: string[]): Promise<Record<string, string>> {
  const flags = profiles.flatMap((profile) => ["--profile", profile]);
  const result = await compose([...flags, "config", "--format", "json"], 30_000);
  if (!result.ok) return {};
  const services = (JSON.parse(result.stdout).services ?? {}) as Record<
    string,
    { image?: string }
  >;
  return Object.fromEntries(
    Object.entries(services).map(([name, service]) => [name, service.image ?? ""]),
  );
}

/**
 * Bring every service running an out-of-date image onto the one the compose
 * file names, one service at a time. Returns the services it recreated.
 *
 * This is how a `docker compose pull` takes effect. The documented update is
 * `pull` and then `up -d`, and `up -d` without a profile only replaces the
 * console — so without this, a release that moved Postgres or Kong to a new
 * version pulled the image and never ran it.
 */
export async function recreateOutdated(): Promise<string[]> {
  const [wanted, running] = await Promise.all([
    serviceImages(["full"]),
    serviceStatuses(),
  ]);
  const disabled = new Set(disabledServices());
  const outdated = outdatedServices(wanted, running).filter((name) =>
    !disabled.has(name)
  );
  await recreateServices(outdated);
  return outdated;
}

/**
 * The dashboard's Restart the stack: start whatever is stopped or missing,
 * bring any service onto a newer image, and restart everything else.
 *
 * It no longer recreates every container. A restart picks up nothing a
 * container reads only when it is created, so a hand-edited `.env` still needs
 * that one service recreated — which is what the key rotations and the LAN
 * switch already do for the settings they change.
 */
export async function restartStack(): Promise<CommandResult> {
  const started = await startStack(["full"]);
  if (!started.ok) return started;
  await recreateOutdated();
  return await restartStackServices();
}

/**
 * Recreate one service, picking up any config file that changed under it.
 *
 * Refuses a service this stack does not run: `up -d` on one would *start* it,
 * which for Caddy means a second process reaching for 80 and 443 on a machine
 * whose operator is already using them.
 */
export function restartService(service: string): Promise<CommandResult> {
  if (disabledServices().includes(service)) {
    return Promise.resolve({
      ok: false,
      stdout: "",
      stderr: `This stack does not run ${service}.`,
    });
  }
  return compose(recreateArgs(service), 120_000);
}

/**
 * The compose arguments that recreate [service], and nothing else.
 *
 * `up -d --force-recreate`, not `restart`: a restarted container keeps the
 * environment it was created with, so a changed .env would not reach it. This
 * is the difference that makes a raised Realtime limit stick.
 *
 * `--no-deps` is the half that was missing, and it was expensive. Without it
 * compose brings a service's dependencies into the same `up`, and
 * `--force-recreate` recreates those too. Kong depends on auth and rest, and
 * both on Postgres, so recreating Kong recreated the database and dropped every
 * connection on the server — on every LAN switch, and on the first key
 * rotation, which is where it showed: `rift-db` had been created two seconds
 * into a rotation that was never meant to touch it. Nothing else reported it,
 * because the stack came back healthy.
 */
export function recreateArgs(service: string): string[] {
  return ["--profile", "full", "up", "-d", "--force-recreate", "--no-deps", service];
}

/**
 * Recreate [services] one after another, stopping at the first that fails.
 *
 * Shared by everything that changes configuration under running containers —
 * the LAN switch and key rotation — because each needs the same two things:
 * `--force-recreate`, so a changed `.env` is actually read, and a failure that
 * names the service and says why in one line.
 */
export async function recreateServices(services: readonly string[]): Promise<void> {
  for (const service of services) {
    const result = await restartService(service);
    if (!result.ok) {
      throw new Error(`Could not start ${service}: ${composeProblem(result.stderr)}`);
    }
  }
}

/**
 * The one line of a compose failure worth showing.
 *
 * Compose narrates every container it touched on stderr and puts the reason
 * last, so handing the whole thing to the page produced twenty lines of
 * "Container rift-db Healthy" above the sentence that mattered.
 */
export function composeProblem(stderr: string): string {
  const lines = stderr.split("\n").map((line) => line.trim()).filter((line) =>
    line.length > 0
  );
  const reason = lines.find((line) => /^Error( response from daemon)?:/i.test(line));
  return (reason ?? lines[lines.length - 1] ?? "docker compose failed")
    .replace(/^Error response from daemon:\s*/i, "");
}

/** Stop everything except the console. */
export async function stopStack(): Promise<CommandResult> {
  const services = (await servicesIn(["full", "studio"])).filter((s) => s !== SELF);
  return compose(
    ["--profile", "full", "--profile", "studio", "stop", ...services],
    120_000,
  );
}

/** The last [lines] of one service's log. */
export async function serviceLogs(service: string, lines = 200): Promise<string> {
  const result = await compose(
    [
      "--profile",
      "full",
      "--profile",
      "studio",
      "logs",
      "--no-color",
      "--tail",
      String(lines),
      service,
    ],
    30_000,
  );
  return result.ok ? result.stdout : result.stderr;
}

/** True if the Docker socket is reachable at all. */
export async function isDockerReachable(): Promise<boolean> {
  try {
    const result = await run("docker", ["version", "--format", "{{.Server.Version}}"], {
      timeoutMs: 15_000,
    });
    return result.code === 0;
  } catch {
    return false;
  }
}

/**
 * Wait until compose has finished converging the project.
 *
 * The console applies upgrades on boot, which means it wants to recreate the
 * functions container while the `docker compose up -d` that started *it* may
 * still be working on the same project. Two compose runs converging one
 * project at once is not a defined thing, so this waits for the stack to look
 * settled first: nothing being created, nothing restarting, and the services
 * that carry a healthcheck reporting something other than `starting`.
 *
 * Returns false on timeout rather than throwing. A caller that cannot get a
 * clean moment should say so and leave the work for a button, not force it.
 */
export async function waitForSettled(
  options: { timeoutMs?: number; pollMs?: number } = {},
): Promise<boolean> {
  const deadline = Date.now() + (options.timeoutMs ?? 120_000);

  while (Date.now() < deadline) {
    const statuses = await serviceStatuses();

    // Nothing at all means compose has not started anything yet, which is not
    // the same as settled.
    if (statuses.length > 0) {
      const busy = statuses.some((service) =>
        service.state === "created" ||
        service.state === "restarting" ||
        service.health === "starting"
      );
      if (!busy) return true;
    }

    await new Promise((resolve) => setTimeout(resolve, options.pollMs ?? 3000));
  }

  return false;
}
