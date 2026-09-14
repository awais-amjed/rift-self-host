import type { OptionField, SetupOptions } from "../setup/options.ts";
import { shell, STREAM_SCRIPT } from "./shell.ts";

/** One input, rendered from its [OptionField] and current value. */
function optionInput(field: OptionField, value: unknown): string {
  if (field.kind === "toggle") {
    return `<div class="field">
      <label for="${field.key}">
        <input id="${field.key}" name="${field.key}" type="checkbox"
               data-kind="toggle" ${value === true ? "checked" : ""}>
        ${field.label}
      </label>
      ${field.hint ? `<p class="hint">${field.hint}</p>` : ""}
    </div>`;
  }

  const type = field.kind === "number"
    ? "number"
    : field.kind === "password"
    ? "password"
    : "text";
  const shown = field.kind === "password" ? "" : String(value ?? "");
  return `<div class="field">
    <label for="${field.key}">${field.label}</label>
    <input id="${field.key}" name="${field.key}" type="${type}" value="${shown}"
           data-kind="${field.kind}">
    ${field.hint ? `<p class="hint">${field.hint}</p>` : ""}
  </div>`;
}

/**
 * The setup wizard, shown while there is no .env.
 *
 * Rendered from [fields] rather than written out, so the form, the defaults
 * and the .env keys cannot drift apart. Values come from a hand-written .env
 * where one exists and from the defaults where it does not — the operator sees
 * what they will get, and changes only what they care about.
 */
export function setupPage(fields: OptionField[], values: SetupOptions): string {
  const plain = fields.filter((f) => !f.advanced).map((f) =>
    optionInput(f, values[f.key])
  ).join("");
  const advanced = fields.filter((f) => f.advanced).map((f) =>
    optionInput(f, values[f.key])
  ).join("");

  return shell(
    "Set up your Rift server",
    `<h1>Set up your Rift server</h1>
<p class="sub">Everything not filled in here is generated. The
  <a href="https://docs.joinrift.app/install/" target="_blank" rel="noopener">installation
  guide</a> explains each choice.</p>

<form id="form" class="panel">
  ${plain}
  <details id="advanced">
    <summary>Ports and console access</summary>
    <p class="hint">Defaults are right for almost every server. Change them if
      this machine already uses one of these ports, or if you are running a
      second Rift server beside an existing one.</p>
    ${advanced}
  </details>
  <button type="submit" id="go">Set up</button>
</form>

<div class="panel" id="progress" style="display:none">
  <ul class="steps" id="steps"></ul>
  <p class="hint" id="note">Pulling images can take several minutes the first time.</p>
</div>

<div class="panel" id="done" style="display:none">
  <h2 style="margin-top:0">Your server is running</h2>
  <p>Paste this into the app's Join form. It is a single-use admin invite:
    whoever uses it first becomes the server's administrator.</p>
  <div class="invite" id="invite"></div>

  <h2>Console password</h2>
  <p>Save this now. You will need it to reload this page as a dashboard, and it
     is not shown again — though it stays in <code>.env</code>, and
     <code>docker compose logs console</code> prints it too.</p>
  <div class="secret"><div class="mono" id="issuedPassword"></div></div>

  <h2>Next</h2>
  <ol class="hint">
    <li>Save the console password in a password manager.</li>
    <li>Join your server with the invite link above.</li>
    <li>Reload this page and sign in. The dashboard has step-by-step help
      beside every heading — start with the Network tab to check which ports
      to open, then make a first backup from the Backups tab.</li>
  </ol>
</div>

<div class="panel" id="failed" style="display:none">
  <h2 style="margin-top:0">Setup stopped</h2>
  <p class="error" id="why"></p>
  <p class="hint">Fix what it says and press Set up again. The full log is in
    <code>docker compose logs console</code>.</p>
</div>`,
    `${STREAM_SCRIPT}
const form = document.getElementById("form");

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  document.getElementById("go").disabled = true;
  document.getElementById("progress").style.display = "block";

  const options = {};
  for (const input of form.querySelectorAll("input[name]")) {
    const raw = input.type === "checkbox" ? "" : input.value.trim();
    // A blank number means "leave the default alone"; sending 0 would be a
    // port choice rather than an absence.
    if (input.dataset.kind === "toggle") {
      options[input.name] = input.checked;
    } else if (input.dataset.kind === "number") {
      if (raw !== "") options[input.name] = Number(raw);
    } else {
      options[input.name] = raw;
    }
  }

  const response = await fetch("/api/setup", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(options),
  });

  await readStream(response, (event) => {
    if (event.step) mark(event.step + (event.detail ? "  (" + event.detail + ")" : ""), event.done);
    if (event.inviteLink) {
      document.getElementById("note").style.display = "none";
      document.getElementById("done").style.display = "block";
      document.getElementById("invite").textContent = event.inviteLink;
      // Not "consolePassword": that id belongs to the form's input above,
      // and getElementById returns the first match — so this wrote
      // textContent onto an <input>, which shows nothing, and the panel
      // stayed blank while the password sat in the log.
      document.getElementById("issuedPassword").textContent = event.consolePassword || "";
    }
    if (event.error) {
      document.getElementById("note").style.display = "none";
      document.getElementById("failed").style.display = "block";
      document.getElementById("why").textContent = event.error;
      document.getElementById("go").disabled = false;
    }
  });
});
`,
  );
}
