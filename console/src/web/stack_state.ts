/** What `.env` says about the stack, as more than one area of routes asks it. */
import { setting } from "../env_file.ts";

/**
 * True once setup has run, as distinct from a `.env` merely existing.
 *
 * The file is not the test, because an operator may write one by hand before
 * ever starting the console — a domain, some ports, a password — and that file
 * describes a stack that has not been built yet. Treating its presence as
 * "configured" showed them a login page for a server that did not exist, and
 * no way to reach setup at all.
 *
 * `JWT_SECRET` is the test instead: it is generated, never something anybody
 * writes by hand, and nothing in the stack works without it.
 */
export function isConfigured(): boolean {
  return setting("JWT_SECRET") !== undefined;
}

/**
 * Whether this stack was *set up* for local testing, as opposed to switched
 * onto the LAN afterwards.
 *
 * The two look alike from the outside and are not the same thing. A stack set
 * up this way has no domain and no certificate and never will; a real one with
 * the switch thrown is still a real server, and everything goes back when the
 * switch does.
 */
export function setupWasLocal(): boolean {
  return setting("RIFT_LOCAL_TESTING") === "true";
}

/** A port from `.env`, or [fallback] when it is missing or not a port. */
export function portSetting(name: string, fallback: number): number {
  const value = Number(setting(name));
  return Number.isInteger(value) && value > 0 ? value : fallback;
}
