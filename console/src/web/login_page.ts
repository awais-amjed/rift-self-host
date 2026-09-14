import { shell } from "./shell.ts";

/** The login form. */
export function loginPage(failed: boolean): string {
  return shell(
    "Rift console",
    `<h1>Rift console</h1>
<p class="sub">Setup showed this password once, and printed it with
<code>docker compose logs console</code>. If the log has rotated away it is
still <code>CONSOLE_PASSWORD</code> in the <code>.env</code> beside your
<code>docker-compose.yml</code>.</p>
<form method="post" action="/login" class="panel">
  <div class="field">
    <label for="password">Console password</label>
    <input id="password" name="password" type="password" autofocus autocomplete="current-password">
  </div>
  ${failed ? '<p class="error">That is not the password.</p>' : ""}
  <button type="submit">Sign in</button>
</form>`,
  );
}
