/**
 * The console's own address, on a terminal — and never its password.
 *
 * It used to print the password, on every start, so anybody who could read
 * `docker compose logs` had the console, and the Docker socket behind it. Setup
 * shows the password once, on the page, and the console keeps only a hash
 * (console_password.ts); the banner says how to get a new one instead.
 *
 * Printed at startup and again when setup finishes. The second call is not a
 * nicety: the container starts *before* setup exists, so the startup banner
 * necessarily says there is no password, and if nothing corrected it the log
 * went on saying so after setup had made one.
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

/** The command that replaces a lost console password. */
export const RESET_COMMAND = "docker compose exec console reset-password";

/** Print the banner. */
export function announce(options: { configured: boolean }): void {
  const rule = "\u2500".repeat(58);

  console.log(`\n${rule}`);
  console.log("  Rift console");
  console.log(`  http://localhost:${consolePort()}`);
  if (options.configured) {
    console.log(`  Lost the password? ${RESET_COMMAND}`);
  } else {
    console.log("  No password yet - set one up at the address above.");
  }
  console.log(`${rule}\n`);
}
