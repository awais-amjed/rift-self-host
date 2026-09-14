import { shell, STREAM_SCRIPT } from "./shell.ts";

/**
 * Shown instead of setup when an encrypted backup sits beside the compose file.
 *
 * The folder a backup extracts to is a server waiting for exactly one thing,
 * the passphrase, and everything after that is the same as an unencrypted
 * restore: the console finds the payload and loads it.
 */
export function restorePage(): string {
  return shell(
    "Restore your Rift server",
    `<h1>Restore your Rift server</h1>
<p class="sub">An encrypted backup is next to the compose file.</p>

<form id="form" class="panel">
  <div class="field">
    <label for="passphrase">Passphrase</label>
    <input id="passphrase" type="password" autocomplete="off" autofocus>
    <p class="hint">The one typed when this backup was made. A wrong passphrase
      changes nothing, so you can try again. A forgotten one cannot be
      recovered — use another copy of the backup if you have one.</p>
  </div>
  <button type="submit" id="go">Restore</button>
  <p class="hint">Restoring loads the database and attachments, then starts
    every service. Leave this page open until it says the server is back.</p>
</form>

<div class="panel" id="progress" style="display:none">
  <ul class="steps" id="steps"></ul>
  <p class="hint">Loading a large backup can take several minutes.</p>
</div>

<div class="panel" id="done" style="display:none">
  <h2 style="margin-top:0">Your server is back</h2>
  <ol class="hint">
    <li>Reload this page and sign in with the console password this server had
      when the backup was made.</li>
    <li>If this is a new machine, point your domain's DNS at it and open the
      same ports as before (the dashboard's Network tab lists them). The server
      must keep the address it had.</li>
    <li>Open the app and check that messages, attachments and a call work.</li>
  </ol>
</div>

<div class="panel" id="failed" style="display:none">
  <h2 style="margin-top:0">Restore stopped</h2>
  <p class="error" id="why"></p>
  <p class="hint">The full log is in <code>docker compose logs console</code>.</p>
</div>`,
    `${STREAM_SCRIPT}
const form = document.getElementById("form");

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  document.getElementById("go").disabled = true;
  document.getElementById("failed").style.display = "none";
  document.getElementById("progress").style.display = "block";

  const response = await fetch("/api/restore", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ passphrase: document.getElementById("passphrase").value }),
  });

  await readStream(response, (event) => {
    if (event.step) mark(event.step, event.done);
    if (event.restored) {
      for (const li of steps.children) li.className = "done";
      form.style.display = "none";
      document.getElementById("done").style.display = "block";
    }
    if (event.error) {
      document.getElementById("failed").style.display = "block";
      document.getElementById("why").textContent = event.error;
      document.getElementById("go").disabled = false;
    }
  });
});
`,
  );
}
