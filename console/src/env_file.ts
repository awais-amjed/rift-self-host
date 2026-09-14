/**
 * Reading the stack's `.env`.
 *
 * The console must not take these values from its own environment, and the
 * reason is a bug worth remembering. It starts *before* setup, when `.env` does
 * not exist — so any variable compose passes it resolves to an empty string and
 * is baked into the container. The console then writes `.env` and shells out to
 * `docker compose`, which inherits that environment; environment beats `.env`
 * in compose's precedence, so the empty value wins and Postgres comes up with
 * no superuser password and crash-loops on a message about `docker run`.
 *
 * So the file on disk is the single source of truth, re-read on each use. That
 * also means setup takes effect immediately: the console never has to restart
 * itself to see what it just wrote, which it could not do anyway — it is the
 * container that would be replaced.
 */
import { join } from "jsr:@std/path@1";

/** Parse the `KEY=value` lines of an env file. */
export function parseEnv(text: string): Record<string, string> {
  const values: Record<string, string> = {};

  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (trimmed.length === 0 || trimmed.startsWith("#")) continue;

    const separator = trimmed.indexOf("=");
    if (separator === -1) continue;

    const key = trimmed.slice(0, separator).trim();
    let value = trimmed.slice(separator + 1).trim();

    // Compose strips one layer of matching quotes; nothing generated here is
    // quoted, but a hand-edited file may be.
    if (value.length >= 2 && (value.startsWith('"') && value.endsWith('"'))) {
      value = value.slice(1, -1);
    } else if (value.length >= 2 && value.startsWith("'") && value.endsWith("'")) {
      value = value.slice(1, -1);
    }

    values[key] = value;
  }

  return values;
}

/** Where the project directory is, both here and on the host. */
function projectDir(): string {
  return Deno.env.get("RIFT_PROJECT_DIR") ?? Deno.cwd();
}

/** The stack's configuration, or an empty object before setup has run. */
export function readEnvFile(directory: string = projectDir()): Record<string, string> {
  try {
    return parseEnv(Deno.readTextFileSync(join(directory, ".env")));
  } catch {
    return {};
  }
}

/**
 * One value, from `.env` first and the process environment second.
 *
 * That order is the point — see the note at the top of this file. The process
 * environment stays as a fallback only for things compose passes deliberately,
 * like `RIFT_PROJECT_DIR`.
 */
export function setting(name: string): string | undefined {
  const value = readEnvFile()[name];
  if (value !== undefined && value.length > 0) return value;

  const fromProcess = Deno.env.get(name);
  return fromProcess !== undefined && fromProcess.length > 0 ? fromProcess : undefined;
}

/**
 * Change one value in the stack's `.env`, in place.
 *
 * Rewriting rather than appending, so re-running setup does not leave two
 * lines that disagree and let compose pick the later one.
 */
export function updateSetting(
  name: string,
  value: string,
  directory: string = projectDir(),
): Promise<void> {
  return updateSettings({ [name]: value }, directory);
}

/**
 * Change several values in `.env` with one write.
 *
 * A key rotation replaces up to eight values that only mean anything together
 * — a JWT is worthless beside a secret that did not sign it — so writing them
 * one at a time would leave a window, and after a crash a file, that is half
 * one generation and half the next. The new file is written beside the old one
 * and renamed over it, which is what makes the swap all or nothing.
 *
 * Every line naming a key is rewritten, not just the first: compose takes the
 * last one, so a duplicate left behind is the one that wins.
 */
export async function updateSettings(
  values: Record<string, string>,
  directory: string = projectDir(),
): Promise<void> {
  const path = join(directory, ".env");
  const text = await Deno.readTextFile(path);

  const seen = new Set<string>();
  const lines = text.split("\n").map((line) => {
    const trimmed = line.trim();
    const separator = trimmed.indexOf("=");
    if (trimmed.startsWith("#") || separator === -1) return line;
    const name = trimmed.slice(0, separator).trim();
    if (!Object.hasOwn(values, name)) return line;
    seen.add(name);
    return `${name}=${values[name]}`;
  });

  // Before the final newline rather than after it, so the file still ends in one.
  const missing = Object.keys(values).filter((name) => !seen.has(name));
  const end = lines.at(-1) === "" ? lines.length - 1 : lines.length;
  lines.splice(end, 0, ...missing.map((name) => `${name}=${values[name]}`));

  const temporary = `${path}.writing`;
  // A leftover from a crash would keep its own permissions, and the mode below
  // only applies to a file this call creates.
  await Deno.remove(temporary).catch(() => {});
  await Deno.writeTextFile(temporary, lines.join("\n"), { mode: 0o600 });
  await Deno.rename(temporary, path);
}
