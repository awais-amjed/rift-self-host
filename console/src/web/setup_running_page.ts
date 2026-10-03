import { shell } from "./shell.ts";

/**
 * What a reload shows while setup is still running.
 *
 * Setup's progress streams to the page that started it, and a reload loses
 * that stream; it does not stop the setup. So this says so, and reloads itself
 * until setup has finished and the page behind it is the login.
 */
export function setupRunningPage(): string {
  return shell(
    "Setting up your Rift server",
    `<h1>Setup is still running</h1>
<div class="panel">
  <p>Reloading the page doesn't stop it. This page checks again every few
    seconds, and shows the sign-in page once setup has finished.</p>
  <p class="hint">The console password and your invite link were on the page
    that started setup. If you closed it, the password is in
    <code>docker compose logs console</code>, and you can make a new invite
    from the <strong>Servers</strong> tab once you're signed in.</p>
</div>`,
    `setTimeout(() => location.reload(), 4000);`,
  );
}
