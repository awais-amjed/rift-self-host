/**
 * Spawning `psql` and `docker`.
 *
 * Exists because of one specific refusal. Deno will not let a process with a
 * narrowed `--allow-run` hand a child an inherited `LD_LIBRARY_PATH` — that
 * variable can make a trusted binary load an untrusted library, so passing it
 * on is treated as equivalent to running arbitrary code and needs blanket
 * `--allow-run`. The `denoland/deno` image sets it, so every subprocess here
 * fails with `NotCapable` and a message about a variable nobody set on purpose.
 *
 * Widening the permission to `--allow-run` would fix it by giving up the thing
 * the narrow permission was for. Building the child's environment explicitly
 * fixes it properly, and has the better property besides: what these
 * subprocesses see is a decision rather than whatever the container inherited.
 */

/** Variables a child must never inherit, whatever the parent was started with. */
const STRIPPED = [
  "LD_LIBRARY_PATH",
  "LD_PRELOAD",
  "DYLD_LIBRARY_PATH",
  "DYLD_INSERT_LIBRARIES",
];

/**
 * The parent's environment minus [STRIPPED], plus [extra].
 *
 * Everything else is kept: `docker compose` reads `COMPOSE_PROJECT_NAME`,
 * `DOCKER_HOST` and `PATH`, and losing any of them silently changes which
 * project it acts on.
 */
export function childEnv(extra: Record<string, string> = {}): Record<string, string> {
  const env = Deno.env.toObject();
  for (const name of STRIPPED) delete env[name];
  return { ...env, ...extra };
}

/** What a finished subprocess produced. */
export interface Output {
  code: number;
  stdout: string;
  stderr: string;
}

/**
 * Run [command] to completion.
 *
 * [timeoutMs] guards against a child that never exits — a `docker compose up`
 * waiting on a healthcheck that will never pass would otherwise hold the
 * request open forever.
 */
export async function run(
  command: string,
  args: string[],
  options: {
    cwd?: string;
    env?: Record<string, string>;
    stdin?: string;
    timeoutMs?: number;
  } = {},
): Promise<Output> {
  const process = new Deno.Command(command, {
    args,
    cwd: options.cwd,
    clearEnv: true,
    env: childEnv(options.env),
    stdin: options.stdin === undefined ? "null" : "piped",
    stdout: "piped",
    stderr: "piped",
  }).spawn();

  if (options.stdin !== undefined) {
    const writer = process.stdin.getWriter();
    await writer.write(new TextEncoder().encode(options.stdin));
    await writer.close();
  }

  const timer = options.timeoutMs === undefined ? null : setTimeout(() => {
    try {
      process.kill("SIGTERM");
    } catch {
      // Finished between the check and the kill.
    }
  }, options.timeoutMs);

  try {
    const { code, stdout, stderr } = await process.output();
    const decoder = new TextDecoder();
    return {
      code,
      stdout: decoder.decode(stdout).trim(),
      stderr: decoder.decode(stderr).trim(),
    };
  } finally {
    if (timer !== null) clearTimeout(timer);
  }
}

/**
 * Run [command] with its standard output written straight to [path].
 *
 * For a database dump or an archive of every attachment, either of which can
 * be larger than the console's memory: the output is never held, only piped.
 */
export async function runToFile(
  command: string,
  args: string[],
  options: { cwd?: string; path: string },
): Promise<{ code: number; stderr: string }> {
  const file = await Deno.open(options.path, {
    write: true,
    create: true,
    truncate: true,
    mode: 0o600,
  });
  const child = new Deno.Command(command, {
    args,
    cwd: options.cwd,
    clearEnv: true,
    env: childEnv(),
    stdin: "null",
    stdout: "piped",
    stderr: "piped",
  }).spawn();
  const [, stderr, status] = await Promise.all([
    child.stdout.pipeTo(file.writable),
    new Response(child.stderr).text(),
    child.status,
  ]);
  return { code: status.code, stderr: stderr.trim() };
}

/** Run [command] with [path] as its standard input, without reading it into memory. */
export async function runFromFile(
  command: string,
  args: string[],
  options: { cwd?: string; path: string },
): Promise<{ code: number; stderr: string }> {
  const file = await Deno.open(options.path, { read: true });
  const child = new Deno.Command(command, {
    args,
    cwd: options.cwd,
    clearEnv: true,
    env: childEnv(),
    stdin: "piped",
    stdout: "null",
    stderr: "piped",
  }).spawn();
  const [piped, stderr, status] = await Promise.all([
    // Settled rather than awaited: a command that exits early closes its end,
    // and the reason worth reporting is its stderr, not a broken pipe.
    file.readable.pipeTo(child.stdin).then(() => null, (error) => error),
    new Response(child.stderr).text(),
    child.status,
  ]);
  if (status.code === 0 && piped !== null) throw piped;
  return { code: status.code, stderr: stderr.trim() };
}
