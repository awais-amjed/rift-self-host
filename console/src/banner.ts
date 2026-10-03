/**
 * The console's own address and password, on a terminal.
 *
 * Printed at startup and again the moment setup generates a password. The
 * second call is not a nicety: the container starts *before* setup exists, so
 * the startup banner necessarily says there is no password — and if nothing
 * ever corrected it, `docker compose logs console` went on saying so after a
 * password had been created. The instruction on the login page pointed at a
 * place the password was not, and the operator was locked out of their own
 * console with no way in but reading .env by hand.
 */
import { setting } from "./env_file.ts";

/**
 * Where the console listens inside its container: always 8080.
 *
 * `CONSOLE_PORT` is the *host* side of the mapping — compose publishes
 * `${CONSOLE_PORT}:8080`, and the healthcheck asks 8080 — so listening on it
 * made a console with a moved port unreachable, and unhealthy, from its first
 * restart after setup.
 */
export const LISTEN_PORT = 8080;

/** Where the operator reaches the console: the host side of the mapping. */
export function consolePort(): number {
  return Number(setting("CONSOLE_PORT") ?? String(LISTEN_PORT));
}

/**
 * Print the banner.
 *
 * [password] is passed in rather than read back, so the call made at the end
 * of setup does not depend on the write to .env having landed and been
 * re-read first.
 */
export function announce(
  options: { password?: string | null; configured: boolean },
): void {
  const rule = "\u2500".repeat(58);

  console.log(`\n${rule}`);
  console.log("  Rift console");
  console.log(`  http://localhost:${consolePort()}`);
  if (options.password) {
    console.log(`  password: ${options.password}`);
  } else if (!options.configured) {
    console.log("  No password yet - set one up at the address above.");
  }
  console.log(`${rule}\n`);
}
