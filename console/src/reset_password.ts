/**
 * `docker compose exec console reset-password`: a new console password.
 *
 * The console keeps only a hash, so a lost password cannot be looked up, only
 * replaced. This prints the new one to the terminal that asked for it — an
 * exec's output, which `docker compose logs` never sees — and nowhere else.
 * Everyone signed in is signed out, since a session belongs to the password
 * it was opened with (web/auth.ts).
 */
import { RESET_COMMAND } from "./banner.ts";
import { setPassword } from "./console_password.ts";
import { randomString } from "./setup/secrets.ts";
import { isConfigured } from "./web/stack_state.ts";

if (import.meta.main) {
  if (!isConfigured()) {
    console.error(
      "This stack has not finished setup. Choose the console password in the " +
        "setup form instead.",
    );
    Deno.exit(1);
  }

  const password = randomString(24);
  await setPassword(password);

  console.log(`
New console password:

  ${password}

Save it now: it is not shown again, and the console keeps only a hash of it.
Everyone signed in to the console has been signed out. Lose it again and run
${RESET_COMMAND} once more.
`);
}
