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

/** One service, as compose sees it. */
export interface ServiceStatus {
  name: string;
  /** created | running | restarting | exited | paused | dead */
  state: string;
  /** healthy | unhealthy | starting, or "" where no healthcheck is defined. */
  health: string;
  /** What compose prints as the status, e.g. "Up 4 minutes (healthy)". */
  status: string;
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

async function compose(args: string[], timeoutMs = 600_000): Promise<CommandResult> {
  const command = new Deno.Command("docker", {
    args: ["compose", ...args],
    cwd: projectDir(),
    stdout: "piped",
    stderr: "piped",
  });

  const process = command.spawn();
  const timer = setTimeout(() => {
    try {
      process.kill("SIGTERM");
    } catch {
      // Already finished between the check and the kill.
    }
  }, timeoutMs);

  try {
    const { code, stdout, stderr } = await process.output();
    const decoder = new TextDecoder();
    return {
      ok: code === 0,
      stdout: decoder.decode(stdout).trim(),
      stderr: decoder.decode(stderr).trim(),
    };
  } finally {
    clearTimeout(timer);
  }
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
  }));
}

/** Bring up every service in [profiles], waiting for healthchecks to pass. */
export function startStack(profiles: string[] = ["full"]): Promise<CommandResult> {
  const flags = profiles.flatMap((profile) => ["--profile", profile]);
  return compose([...flags, "up", "-d", "--wait", "--remove-orphans"]);
}

/** Recreate one service, picking up any config file that changed under it. */
export function restartService(service: string): Promise<CommandResult> {
  // `up -d --force-recreate`, not `restart`: a restarted container keeps the
  // environment it was created with, so a changed .env would not reach it.
  // This is the difference that makes a raised Realtime limit stick.
  return compose(["--profile", "full", "up", "-d", "--force-recreate", service], 120_000);
}

/** Stop everything except the console. */
export function stopStack(): Promise<CommandResult> {
  return compose(["--profile", "full", "--profile", "studio", "stop"], 120_000);
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
    const command = new Deno.Command("docker", {
      args: ["version", "--format", "{{.Server.Version}}"],
      stdout: "piped",
      stderr: "piped",
    });
    const { code } = await command.output();
    return code === 0;
  } catch {
    return false;
  }
}
