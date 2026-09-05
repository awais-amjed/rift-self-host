/**
 * The console's one page.
 *
 * Served as a single string with its CSS and script inline. No build step, no
 * bundler, no dependency that has to be fetched at runtime — the console has
 * to work on a machine whose whole reason for existing is that it is not yet
 * finished being set up, and a page that needs a CDN is a page that fails
 * exactly then.
 */

import type { OptionField, SetupOptions } from "../setup/options.ts";

/** Rift's palette, matching the app's default (indigo, dark). */
const STYLE = `
:root {
  color-scheme: dark;
  --bg: #08080B; --panel: #0D0D11; --inset: #14141A; --raised: #1A1A21;
  --text: #F4F4F8; --dim: #C6C7CF; --faint: #8B8C96;
  --line: rgba(255,255,255,0.09);
  --accent: #7B83FF; --accent-bright: #9BA3FF;
  --ok: #34D399; --warn: #FBBF24; --fail: #F87171;
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg); color: var(--text);
  font: 15px/1.55 ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
}
main { max-width: 760px; margin: 0 auto; padding: 48px 24px 96px; }
h1 { font-size: 24px; letter-spacing: -0.02em; margin: 0 0 6px; }
h2 { font-size: 15px; margin: 32px 0 12px; color: var(--dim); font-weight: 600; }
p { color: var(--dim); margin: 0 0 16px; }
.sub { color: var(--faint); margin-bottom: 32px; }
.panel {
  background: var(--panel); border: 1px solid var(--line);
  border-radius: 12px; padding: 20px; margin-bottom: 16px;
}
label { display: block; font-size: 12px; text-transform: uppercase;
  letter-spacing: 0.06em; color: var(--faint); margin: 0 0 6px; }
input {
  width: 100%; padding: 11px 13px; background: var(--inset); color: var(--text);
  border: 1px solid var(--line); border-radius: 8px; font-size: 15px;
  font-family: inherit;
}
input:focus { outline: none; border-color: var(--accent); }
.field { margin-bottom: 18px; }
.hint { font-size: 13px; color: var(--faint); margin: 6px 0 0; }
button {
  background: linear-gradient(135deg, var(--accent), #A56BFA); color: #fff;
  border: 0; border-radius: 8px; padding: 11px 20px; font-size: 15px;
  font-weight: 600; font-family: inherit; cursor: pointer;
}
button:disabled { opacity: 0.5; cursor: default; }
button.quiet { background: var(--inset); color: var(--dim); border: 1px solid var(--line); }
table { width: 100%; border-collapse: collapse; font-size: 14px; }
td { padding: 9px 0; border-bottom: 1px solid var(--line); vertical-align: top; }
tr:last-child td { border-bottom: 0; }
td.name { color: var(--dim); width: 40%; }
.dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%;
  margin-right: 8px; vertical-align: 1px; }
.dot.ok { background: var(--ok); } .dot.warn { background: var(--warn); }
.dot.fail { background: var(--fail); } .dot.unknown { background: var(--faint); }
code, .mono { font-family: ui-monospace, "SF Mono", Menlo, monospace; font-size: 13px; }
.invite {
  background: var(--inset); border: 1px solid var(--accent);
  border-radius: 8px; padding: 14px; word-break: break-all;
  font-family: ui-monospace, monospace; font-size: 14px; color: var(--accent-bright);
}
.steps { list-style: none; padding: 0; margin: 0; font-size: 14px; }
.steps li { padding: 7px 0; color: var(--faint); }
.steps li.active { color: var(--text); }
.steps li.done { color: var(--dim); }
.steps li::before { content: "◦ "; }
.steps li.done::before { content: "✓ "; color: var(--ok); }
.steps li.active::before { content: "→ "; color: var(--accent-bright); }
.error { color: var(--fail); white-space: pre-wrap; font-size: 14px; }
.secret { display: flex; gap: 8px; align-items: center; }
.secret .mono { flex: 1; background: var(--inset); border: 1px solid var(--line);
  border-radius: 6px; padding: 8px 10px; overflow-x: auto; white-space: nowrap; }
.secret .mono.masked { color: var(--faint); letter-spacing: 0.18em; user-select: none; }
.secret button { padding: 8px 12px; font-size: 13px; font-weight: 500; }
.toggle { display: flex; gap: 10px; align-items: center; font-size: 14px;
  color: var(--dim); text-transform: none; letter-spacing: 0; cursor: pointer; }
.toggle input { width: auto; margin: 0; cursor: pointer; }
details { margin: 4px 0 20px; }
summary { cursor: pointer; color: var(--dim); font-size: 14px; padding: 6px 0; }
details[open] summary { margin-bottom: 10px; }
.warn { display: flex; gap: 10px; font-size: 13px; color: var(--warn);
  background: rgba(251,191,36,0.07); border: 1px solid rgba(251,191,36,0.22);
  border-radius: 8px; padding: 10px 12px; margin: 8px 0 0; }
`;

function shell(title: string, body: string, script = ""): string {
  return `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>${title}</title>
<style>${STYLE}</style>
</head><body><main>${body}</main>
${script ? `<script>${script}</script>` : ""}
</body></html>`;
}

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

/** One input, rendered from its [OptionField] and current value. */
function optionInput(field: OptionField, value: unknown): string {
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
<p class="sub">Everything not filled in here is generated.</p>

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
  <p>Paste this into the app's Join form. It is a single-use admin invite.</p>
  <div class="invite" id="invite"></div>

  <h2>Console password</h2>
  <p>Save this now. You will need it to reload this page as a dashboard, and it
     is not shown again — though it stays in <code>.env</code>, and
     <code>docker compose logs console</code> prints it too.</p>
  <div class="secret"><div class="mono" id="issuedPassword"></div></div>
</div>

<div class="panel" id="failed" style="display:none">
  <h2 style="margin-top:0">Setup stopped</h2>
  <p class="error" id="why"></p>
</div>`,
    `
const form = document.getElementById("form");
const steps = document.getElementById("steps");
const seen = new Map();

function mark(step, done) {
  let li = seen.get(step);
  if (!li) {
    li = document.createElement("li");
    li.textContent = step;
    steps.appendChild(li);
    seen.set(step, li);
  }
  for (const other of steps.children) {
    if (other.className === "active") other.className = "done";
  }
  li.className = done ? "done" : "active";
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  document.getElementById("go").disabled = true;
  document.getElementById("progress").style.display = "block";

  const options = {};
  for (const input of form.querySelectorAll("input[name]")) {
    const raw = input.value.trim();
    // A blank number means "leave the default alone"; sending 0 would be a
    // port choice rather than an absence.
    if (input.dataset.kind === "number") {
      if (raw !== "") options[input.name] = Number(raw);
    } else {
      options[input.name] = raw;
    }
  }
  const body = JSON.stringify(options);

  const response = await fetch("/api/setup", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body,
  });

  // Newline-delimited JSON, streamed as each step finishes, so a five-minute
  // image pull does not look like a hang.
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";

  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split("\\n");
    buffer = lines.pop();

    for (const line of lines) {
      if (!line.trim()) continue;
      const event = JSON.parse(line);
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
    }
  }
});
`,
  );
}

/** The running dashboard. */
export function dashboardPage(domain: string): string {
  return shell(
    "Rift console",
    `<h1>${domain}</h1>
<p class="sub">Rift server console</p>

<h2>Release</h2>
<div class="panel">
  <table id="version"><tr><td class="name">Loading…</td></tr></table>
  <div id="upgradeBox" style="display:none;margin-top:14px">
    <button id="applyUpgrade">Apply this release</button>
    <p class="hint" id="upgradeHint"></p>
  </div>
  <p class="error" id="upgradeError" style="display:none"></p>

  <label class="toggle" style="margin-top:16px">
    <input type="checkbox" id="autoApply">
    <span>Apply a new release automatically on start</span>
  </label>
  <p class="hint">A pull brings new endpoints and migrations as well as new
    console code, and only the console code runs by itself — so with this off,
    an updated stack keeps serving the old ones until you press Apply. Turn it
    off if a schema change should never happen merely because a machine
    rebooted.</p>
</div>

<h2>Health</h2>
<div class="panel"><table id="checks"><tr><td class="name">Loading…</td></tr></table></div>

<h2>Containers</h2>
<div class="panel"><table id="services"><tr><td class="name">Loading…</td></tr></table></div>

<h2>Servers</h2>
<div class="panel">
  <table id="servers"><tr><td class="name">Loading…</td></tr></table>
  <div class="field" style="margin:18px 0 0">
    <label for="newServer">Create a server</label>
    <div class="secret">
      <input id="newServer" placeholder="My Server" style="flex:1">
      <button id="createServer">Create</button>
    </div>
    <p class="hint">Everything else a server needs — the service key, the voice
      URL and its credentials — is already here, so this is the whole form. The
      app's "Create server" dialog asks for all of it because it cannot know
      any of it.</p>
  </div>
  <p class="error" id="serverError" style="display:none"></p>
  <div id="newInvite" style="display:none">
    <h2>Invite link</h2>
    <p>Paste this into the app's Join form.</p>
    <div class="invite" id="newInviteLink"></div>
  </div>
</div>

<h2>Credentials</h2>
<div class="panel" id="secrets"></div>

<h2>Actions</h2>
<div class="panel">
  <button class="quiet" id="restart">Restart the stack</button>
  <p class="hint">Recreates every container, picking up any configuration change.</p>
</div>`,
    `
async function load() {
  const state = await (await fetch("/api/status")).json();

  document.getElementById("checks").innerHTML = state.checks.map((check) =>
    '<tr><td class="name"><span class="dot ' + check.level + '"></span>' + check.name +
    '</td><td>' + check.detail + '</td></tr>'
  ).join("") || '<tr><td class="name">No checks ran.</td></tr>';

  document.getElementById("services").innerHTML = state.services.map((service) => {
    const level = service.health === "unhealthy" ? "fail"
      : service.state === "running" ? (service.health === "starting" ? "warn" : "ok")
      : "fail";
    return '<tr><td class="name"><span class="dot ' + level + '"></span>' + service.name +
      '</td><td>' + service.status + '</td></tr>';
  }).join("") || '<tr><td class="name">Nothing is running.</td></tr>';

  // Secret rows render masked and stay masked across the ten-second refresh:
  // a value that reappears on its own is one that ends up on a shared screen
  // because nobody noticed it come back.
  const revealed = window._revealed || (window._revealed = new Set());

  await loadVersion();
  await loadServers();

  document.getElementById("secrets").innerHTML = state.secrets.map((entry, i) => {
    const shown = !entry.secret || revealed.has(entry.name);
    const body = shown ? escapeHtml(entry.value) : "\u2022".repeat(28);
    return '<div class="field"><label>' + escapeHtml(entry.name) + '</label>' +
      '<div class="secret"><div class="mono' + (shown ? '' : ' masked') + '">' + body + '</div>' +
      (entry.secret
        ? '<button class="quiet" data-reveal="' + i + '">' + (shown ? 'Hide' : 'Reveal') + '</button>' +
          '<button class="quiet" data-copy="' + i + '">Copy</button>'
        : '') +
      '</div>' +
      (shown && entry.note ? '<p class="warn">' + escapeHtml(entry.note) + '</p>' : '') +
      '</div>';
  }).join("");

  for (const button of document.querySelectorAll("[data-reveal]")) {
    button.addEventListener("click", () => {
      const entry = state.secrets[Number(button.dataset.reveal)];
      revealed.has(entry.name) ? revealed.delete(entry.name) : revealed.add(entry.name);
      load();
    });
  }
  for (const button of document.querySelectorAll("[data-copy]")) {
    button.addEventListener("click", async () => {
      const entry = state.secrets[Number(button.dataset.copy)];
      await navigator.clipboard.writeText(entry.value);
      button.textContent = "Copied";
      setTimeout(() => (button.textContent = "Copy"), 1500);
    });
  }
}

/// Values here are ours, but they are drawn with innerHTML and one of them is
/// operator-supplied (the domain), so they are escaped rather than trusted.
function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[c]);
}

async function loadVersion() {
  const v = await (await fetch("/api/version")).json();
  const rows = [];
  if (v.unknown) {
    rows.push(["Release", "Could not be read — the database may be down."]);
  } else {
    rows.push(["This image", escapeHtml(v.imageVersion)]);
    rows.push(["This stack", escapeHtml(v.appliedVersion || "not recorded")]);
    if (v.pendingMigrations.length) {
      rows.push(["Migrations waiting", v.pendingMigrations.length + " to apply"]);
    }
    if (v.driftedMigrations.length) {
      rows.push(["Changed after running", escapeHtml(v.driftedMigrations.join(", "))]);
    }
  }
  document.getElementById("version").innerHTML = rows
    .map(([k, val]) => '<tr><td class="name">' + k + "</td><td>" + val + "</td></tr>")
    .join("");

  const toggle = document.getElementById("autoApply");
  toggle.checked = v.autoApply !== false;

  const needed = !v.unknown && v.needed;
  document.getElementById("upgradeBox").style.display = needed ? "block" : "none";
  document.getElementById("upgradeHint").textContent = needed
    ? (v.autoApply
      ? "This normally happens by itself on start. Press it if a reload was left undone."
      : "Automatic applying is off (RIFT_AUTO_APPLY=false), so this is the way to do it.")
    : "";
}

document.getElementById("autoApply").addEventListener("change", async (event) => {
  event.target.disabled = true;
  await fetch("/api/auto-apply", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ enabled: event.target.checked }),
  });
  event.target.disabled = false;
  loadVersion();
});

document.getElementById("applyUpgrade").addEventListener("click", async (event) => {
  const error = document.getElementById("upgradeError");
  error.style.display = "none";
  event.target.disabled = true;
  event.target.textContent = "Applying…";

  const body = await (await fetch("/api/upgrade", { method: "POST" })).json();

  event.target.disabled = false;
  event.target.textContent = "Apply this release";
  if (body.error) {
    error.textContent = body.error;
    error.style.display = "block";
  }
  load();
});

async function loadServers() {
  const data = await (await fetch("/api/servers")).json();
  const linkFor = (id) => (data.invites.find((i) => i.serverId === id) || {}).link;

  document.getElementById("servers").innerHTML = data.servers.map((server) => {
    const link = linkFor(server.id);
    return '<tr><td class="name">' + escapeHtml(server.name) + '</td><td>' +
      server.memberCount + ' member' + (server.memberCount === 1 ? '' : 's') + ' · ' +
      server.channelCount + ' channel' + (server.channelCount === 1 ? '' : 's') +
      '<div class="secret" style="margin-top:8px">' +
      (link
        ? '<div class="mono">' + escapeHtml(link) + '</div>' +
          '<button class="quiet" data-copy-invite="' + escapeHtml(link) + '">Copy</button>'
        : '<button class="quiet" data-invite="' + server.id + '">Create invite link</button>') +
      '</div></td></tr>';
  }).join("") || '<tr><td class="name">No servers yet.</td></tr>';

  for (const button of document.querySelectorAll("[data-invite]")) {
    button.addEventListener("click", async () => {
      button.disabled = true;
      const res = await fetch("/api/servers/invite", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ serverId: button.dataset.invite, maxUses: 1 }),
      });
      const body = await res.json();
      if (body.link) loadServers();
      else { button.disabled = false; alert(body.error || "Could not create an invite."); }
    });
  }
  for (const button of document.querySelectorAll("[data-copy-invite]")) {
    button.addEventListener("click", async () => {
      await navigator.clipboard.writeText(button.dataset.copyInvite);
      button.textContent = "Copied";
      setTimeout(() => (button.textContent = "Copy"), 1500);
    });
  }
}

document.getElementById("createServer").addEventListener("click", async (event) => {
  const input = document.getElementById("newServer");
  const error = document.getElementById("serverError");
  error.style.display = "none";
  event.target.disabled = true;
  event.target.textContent = "Creating…";

  const res = await fetch("/api/servers/create", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name: input.value.trim() }),
  });
  const body = await res.json();

  event.target.disabled = false;
  event.target.textContent = "Create";
  if (body.inviteLink) {
    input.value = "";
    document.getElementById("newInvite").style.display = "block";
    document.getElementById("newInviteLink").textContent = body.inviteLink;
    loadServers();
  } else {
    error.textContent = body.error || "Could not create the server.";
    error.style.display = "block";
  }
});

document.getElementById("restart").addEventListener("click", async (event) => {
  event.target.disabled = true;
  event.target.textContent = "Restarting…";
  await fetch("/api/restart", { method: "POST" });
  event.target.disabled = false;
  event.target.textContent = "Restart the stack";
  load();
});

load();
setInterval(load, 10000);
`,
  );
}

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
