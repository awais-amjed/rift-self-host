import { shell } from "./shell.ts";

/**
 * Shown instead of setup when the console is reachable from the network and
 * has no password yet.
 *
 * Refusing rather than warning, because there is nothing to protect the window
 * with: until setup runs there is no password, and this interface can start,
 * stop and replace every container on the host. An operator who has widened
 * the bind before setting anything up has almost certainly not thought about
 * that, and the fix is one line.
 */
export function exposedPage(): string {
  return shell(
    "Rift console",
    `<h1>Not from here</h1>
<p class="sub">Set this up over the loopback first.</p>
<div class="panel">
  <p class="warn">This console can start, stop and replace every container on
    this machine, and it has no password until setup has run. It is published
    on a network interface, so it is refusing to do anything until that is one
    or the other.</p>
  <h2>Either</h2>
  <p>Put it back on the loopback — remove <code>CONSOLE_BIND</code> from your
     <code>.env</code>, or set it to <code>127.0.0.1</code> — and reach it
     through a tunnel:</p>
  <div class="secret"><div class="mono">ssh -L 8080:localhost:8080 you@this-machine</div></div>
  <h2>Or</h2>
  <p>Give it a password before it is reachable, by putting one in
     <code>.env</code> beside your <code>docker-compose.yml</code>:</p>
  <div class="secret"><div class="mono">CONSOLE_PASSWORD=something-long-and-random</div></div>
  <p class="hint">Then <code>docker compose up -d --force-recreate console</code>.</p>
</div>`,
  );
}
