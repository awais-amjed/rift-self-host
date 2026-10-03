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
  return setting("JWT_SECRET") !== undefined && !setupUnfinished();
}

/**
 * Setup has written `.env` and not yet reached its end: still running, or
 * stopped part-way.
 *
 * `.env` is written by setup's first step, secrets and console password
 * included, so `JWT_SECRET` alone said "configured" for the whole of setup. A
 * reload in that window showed a login page for a password that had not been
 * shown to anybody yet, and a setup that stopped could never be run again.
 * `RIFT_SETUP` is `running` from the first step and `done` after the last;
 * a stack set up before it existed has neither, and counts as done.
 */
export function setupUnfinished(): boolean {
  return setting("RIFT_SETUP") === "running";
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
