/**
 * Pointing a real server's voice at the LAN for an afternoon, and putting it
 * back.
 *
 * The problem this solves is narrow. A server set up properly has a name and a
 * certificate, and everything works — except that trying a change on a machine
 * on your own network means voice has to reach LiveKit, and LiveKit is behind a
 * proxy answering for a domain that resolves to somewhere else. So the call
 * connects to the live server or not at all.
 *
 * What the switch does is therefore small on purpose: it publishes LiveKit and
 * the API directly, and rewrites `servers.livekit_url`. That column is the
 * *only* address a client takes from the server — every HTTP address it builds
 * comes from the `supabaseUrl` it stored when it joined — so it is also the
 * only thing that has to move, and the only thing that has to move back.
 *
 * Two costs, both of which the dashboard says out loud rather than burying
 * here:
 *
 *  - While it is on, voice points at the LAN **for everybody**. A member
 *    connecting from outside can still read and send messages; they cannot
 *    call.
 *  - The LAN link is for testing, not for onboarding. Somebody who joins
 *    through it derives their identity from the LAN address, so they are
 *    stranded the moment it is switched off — the same trap as a local-testing
 *    stack, and for the same reason.
 *
 * The previous URLs are kept in `rift_console.state` rather than in a column of
 * their own: it is a console convenience, and a convenience does not earn a
 * migration on everybody's server.
 */
import {
  FIELD_SEPARATOR,
  literal,
  type PostgresTarget,
  queryRows,
  runSql,
} from "./postgres.ts";
import { clearState, readState, writeState } from "./state.ts";
import { projectDir, recreateServices } from "./docker.ts";
import { setting } from "./env_file.ts";
import { behindCaddy, type Publishing, writeOverride } from "./setup/config_files.ts";

/** Where the state row lives. */
export const LOCAL_TESTING = "local_testing";

/** Where LiveKit's signalling is published when nothing is in front of it. */
export const SIGNALLING_PORT = 7880;

/** Where the API is published beside the proxy, rather than through it. */
export const DEFAULT_API_PORT = 18000;

/** A stack that is currently switched to the LAN. */
export interface LocalTesting {
  /** The address clients reach, e.g. `192.168.1.6`. */
  address: string;
  /** Where the API is published. Not 443: the proxy still has that. */
  port: number;
  /** Every server's `livekit_url` as it was before the switch. */
  restore: Record<string, string>;
}

/** The LAN address of the API while the switch is on. */
export function localPublicUrl(local: LocalTesting): string {
  return `http://${local.address}:${local.port}`;
}

/** The LAN address of voice while the switch is on. */
export function localLivekitUrl(local: LocalTesting): string {
  return `ws://${local.address}:${SIGNALLING_PORT}`;
}

/**
 * Whether this stack is switched to the LAN, and where to.
 *
 * A row that cannot be parsed is treated as absent rather than thrown: the
 * dashboard has to render, and an unreadable row is one an operator can undo
 * by pressing the switch.
 */
export async function readLocalTesting(
  target: PostgresTarget,
): Promise<LocalTesting | null> {
  const raw = await readState(target, LOCAL_TESTING);
  if (raw === null) return null;
  try {
    const parsed = JSON.parse(raw) as Partial<LocalTesting>;
    if (typeof parsed.address !== "string" || parsed.address.length === 0) return null;
    return {
      address: parsed.address,
      port: Number(parsed.port) || DEFAULT_API_PORT,
      restore: parsed.restore ?? {},
    };
  } catch {
    return null;
  }
}

/** Read a port from `.env`, or [fallback] if it does not say. */
function envPort(name: string, fallback: number): number {
  const parsed = Number(setting(name));
  return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback;
}

/**
 * The ports this stack already publishes, and what has each.
 *
 * Checked before the switch rather than discovered afterwards. Docker reports a
 * collision as a wall of container status with one useful line at the bottom,
 * arriving a minute in and after the compose override has already been written
 * — and the port an operator reaches for first is 8080, which is the console
 * they are pressing the button on.
 */
export function stackPorts(): Record<number, string> {
  const taken: Record<number, string> = {};
  const claim = (port: number, owner: string) => {
    if (!(port in taken)) taken[port] = owner;
  };
  claim(envPort("CONSOLE_PORT", 8080), "this console");
  claim(envPort("HTTP_PORT", 80), "the HTTP port");
  claim(envPort("HTTPS_PORT", 443), "the HTTPS port");
  claim(envPort("LIVEKIT_TCP_PORT", 7881), "voice");
  claim(SIGNALLING_PORT, "LiveKit's signalling, which this switch publishes");
  return taken;
}

/** Complain about an address or port that would produce a stack that cannot start. */
export function problemWithAddress(
  address: string,
  port: number,
  taken: Record<number, string> = stackPorts(),
): string | null {
  const trimmed = address.trim();
  if (trimmed.length === 0) {
    return "Enter the address this machine has on your network, such as 192.168.1.6.";
  }
  if (/^https?:\/\//i.test(trimmed)) {
    return "Enter the address on its own, without http:// or https://.";
  }
  if (trimmed.includes("/") || trimmed.includes(":")) {
    return "Enter the address on its own, without a port or a path.";
  }
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    return "The port must be between 1 and 65535.";
  }
  const owner = taken[port];
  if (owner) {
    return `Port ${port} is already ${owner}. Pick another — ${DEFAULT_API_PORT} ` +
      "is free unless something else on this machine has it.";
  }
  return null;
}

/** `livekit_url` for every server on this stack, keyed by id. */
async function livekitUrls(target: PostgresTarget): Promise<Record<string, string>> {
  const rows = await queryRows(target, "SELECT id, livekit_url FROM servers");
  const urls: Record<string, string> = {};
  for (const row of rows) {
    const [id, url] = row.split(FIELD_SEPARATOR);
    if (id) urls[id] = url ?? "";
  }
  return urls;
}

/** Point every server's voice at [url]. */
async function setLivekitUrl(target: PostgresTarget, url: string): Promise<void> {
  const result = await runSql(
    target,
    `UPDATE servers SET livekit_url = ${literal(url)};`,
    { singleTransaction: true },
  );
  if (!result.ok) throw new Error(`Could not update the voice URL: ${result.error}`);
}

/**
 * Put each server back to the URL it had, and anything unremembered onto
 * [fallback].
 *
 * A server created while the switch was on has no remembered value, because it
 * did not exist when the switch was thrown. Leaving it pointed at the LAN would
 * be the one server on the stack whose voice never comes back, so it takes the
 * address the stack would have given it.
 */
export function restoreStatements(
  restore: Record<string, string>,
  present: string[],
  fallback: string,
): string[] {
  return present
    .filter((id) => /^[0-9a-fA-F-]{36}$/.test(id))
    .map((id) => {
      const url = restore[id] ?? fallback;
      return `UPDATE servers SET livekit_url = ${literal(url)} WHERE id = ${
        literal(id)
      };`;
    });
}

async function restoreLivekitUrls(
  target: PostgresTarget,
  restore: Record<string, string>,
  fallback: string,
): Promise<void> {
  const present = Object.keys(await livekitUrls(target));
  const statements = restoreStatements(restore, present, fallback);
  if (statements.length === 0) return;
  const result = await runSql(target, statements.join("\n"), { singleTransaction: true });
  if (!result.ok) throw new Error(`Could not restore the voice URL: ${result.error}`);
}

/**
 * What this stack publishes when the switch is *not* on.
 *
 * Not always "nothing". A stack whose operator brought their own reverse proxy
 * publishes Kong on the loopback for it, permanently — so switching back has to
 * restore that rather than delete the file, which is what a renderer for the
 * switch alone would have done.
 */
function restingPublishing(): Publishing {
  if (setting("RIFT_OWN_PROXY") !== "true") return behindCaddy;
  return {
    apiPort: envPort("RIFT_PROXY_PORT", DEFAULT_API_PORT),
    bind: "127.0.0.1",
    lanAddress: null,
  };
}

/** What it publishes while the switch is on: the LAN, for other machines. */
function localPublishing(local: LocalTesting): Publishing {
  return {
    apiPort: local.port,
    bind: "0.0.0.0",
    lanAddress: local.address,
  };
}

/** Kong publishes the API; LiveKit publishes signalling. Both change here. */
function recreate(): Promise<void> {
  return recreateServices(["kong", "livekit"]);
}

/**
 * Switch this stack to the LAN.
 *
 * Switching on while already on is a change of address, not a second switch:
 * the remembered URLs are the ones from the first time, and re-reading them
 * now would remember the LAN address as the thing to go back to.
 */
export async function turnOn(
  target: PostgresTarget,
  address: string,
  port: number,
): Promise<LocalTesting> {
  const problem = problemWithAddress(address, port);
  if (problem) throw new Error(problem);

  const already = await readLocalTesting(target);
  const local: LocalTesting = {
    address: address.trim(),
    port,
    restore: already?.restore ?? await livekitUrls(target),
  };

  // The containers move first, and the database only once they have. Publishing
  // a port is the one step here that can fail — something else may hold it —
  // and doing it first means a failure leaves the server exactly as it was
  // rather than pointed at an address that never came up.
  await writeOverride(projectDir(), localPublishing(local));
  try {
    await recreate();
  } catch (error) {
    await writeOverride(projectDir(), restingPublishing());
    // Best effort: if this fails too the override is already gone, so
    // "Restart the stack" puts everything back.
    await recreate().catch(() => {});
    throw error;
  }

  await writeState(target, LOCAL_TESTING, JSON.stringify(local));
  await setLivekitUrl(target, localLivekitUrl(local));
  return local;
}

/**
 * Put it back.
 *
 * [fallback] is the voice URL this stack would hand out — where a server
 * created while the switch was on ends up.
 *
 * The remembered row is dropped last and unconditionally: a stash left behind
 * is a set of addresses that gets staler every day, waiting to be written over
 * whatever the operator has since moved to.
 */
export async function turnOff(
  target: PostgresTarget,
  fallback: string,
): Promise<void> {
  const local = await readLocalTesting(target);
  if (local !== null) await restoreLivekitUrls(target, local.restore, fallback);
  await clearState(target, LOCAL_TESTING);
  await writeOverride(projectDir(), restingPublishing());
  // Last, because everything above has already made this a normal server. If
  // the containers sulk, "Restart the stack" is the whole of the repair.
  await recreate();
}
