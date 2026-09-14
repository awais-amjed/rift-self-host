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
.rotation { display: flex; gap: 16px; align-items: flex-start; justify-content: space-between;
  padding: 14px 0; border-top: 1px solid var(--line); }
.rotation:first-child { border-top: 0; padding-top: 0; }
.rotation:last-child { padding-bottom: 0; }
.rotation button { flex-shrink: 0; }
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
.block {
  font-family: ui-monospace, "SF Mono", Menlo, monospace; font-size: 12.5px;
  line-height: 1.5; background: var(--inset); border: 1px solid var(--line);
  border-radius: 8px; padding: 12px 14px; margin: 0; color: var(--dim);
  white-space: pre; overflow-x: auto; max-height: 320px; overflow-y: auto;
}
.secret button { padding: 8px 12px; font-size: 13px; font-weight: 500; }
details { margin: 4px 0 20px; }
summary { cursor: pointer; color: var(--dim); font-size: 14px; padding: 6px 0; }
details[open] summary { margin-bottom: 10px; }
.warn { display: flex; gap: 10px; font-size: 13px; color: var(--warn);
  background: rgba(251,191,36,0.07); border: 1px solid rgba(251,191,36,0.22);
  border-radius: 8px; padding: 10px 12px; margin: 8px 0 0; }
`;

/** The server-side half of the page's own `escapeHtml`. */
function escapeAttribute(value: string): string {
  return value.replace(
    /[&<>"']/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!,
  );
}

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
export function dashboardPage(domain: string, localTesting = false): string {
  // Said on every load, not once at setup. A throwaway stack that has been
  // running for a fortnight stops looking like one, and the thing that makes it
  // throwaway — its address, which every member's identity derives from — is
  // invisible from here.
  const banner = localTesting
    ? `<p class="warn" style="margin:0 0 22px"><span>This is a
       <strong>local testing</strong> stack: plain HTTP on a LAN address, no
       certificate, and unreachable from any phone. It cannot become a real
       server — every member's identity is derived from the address they joined
       at, so changing it makes them strangers and their history unreadable.
       Build a real one when you want to keep it.</span></p>`
    : "";

  return shell(
    "Rift console",
    // Escaped like every other operator-supplied value on this page. The
    // domain comes out of `.env`, which somebody may have written by hand.
    `<h1>${escapeAttribute(domain)}</h1>
<p class="sub">Rift server console</p>
${banner}

<h2>Release</h2>
<div class="panel">
  <table id="version"><tr><td class="name">Loading…</td></tr></table>
  <div id="upgradeBox" style="display:none;margin-top:14px">
    <button id="applyUpgrade">Apply this release</button>
    <p class="hint" id="upgradeHint"></p>
  </div>
  <p class="error" id="upgradeError" style="display:none"></p>

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

<div id="proxySection" style="display:none">
<h2>Your reverse proxy</h2>
<div class="panel">
  <p>This stack does not run Caddy, so nothing is listening on 80 or 443 for
    it. Point your proxy at both upstreams below — routing everything to the
    API is the mistake to avoid, because it leaves messages working and calls
    failing. Voice media is the third row and does not pass through any proxy:
    it needs those ports open, or a call connects with no sound.</p>
  <div id="proxyUpstreams"></div>
  <p class="hint">If your proxy runs in a container, attach it to this stack's
    compose network and use <code>kong:8000</code> and
    <code>livekit:7880</code> instead; nothing then needs to be published at
    all.</p>
  <h2 style="margin-top:24px">If your proxy is Caddy</h2>
  <p>This is the stack's own Caddyfile, repointed at those upstreams.</p>
  <pre class="block" id="proxyCaddyfile"></pre>
  <button class="quiet" id="copyCaddyfile" style="margin-top:10px">Copy</button>
</div>
</div>

<div id="localSection" style="display:none">
<h2>Local testing</h2>
<div class="panel">
  <p id="localSummary"></p>
  <div class="field" id="localFields">
    <label for="localAddress">This machine's address on your network</label>
    <div class="secret">
      <input id="localAddress" placeholder="192.168.1.6" style="flex:1">
      <input id="localPort" type="number" style="width:120px" aria-label="API port">
    </div>
    <p class="hint">The second box is which port to use — leave it unless
      something else on this machine already has it. Your domain keeps working
      the whole time.</p>
  </div>
  <div id="localAddresses" style="display:none"></div>
  <p class="error" id="localError" style="display:none;margin:0 0 14px"></p>
  <button id="localToggle">Switch voice to this network</button>
  <p class="warn"><span>Use this for testing on your own network. While it is
    on, people outside it cannot join a call — and the local link only works
    from here, so do not send it to anyone.</span></p>
</div>
</div>

<h2>Credentials</h2>
<div class="panel" id="secrets"></div>

<h2>Backups</h2>
<div class="panel">
  <p>Saves the database, the attachments and <code>.env</code> as one file in
    <code>backups/</code>, next to the compose file. Copy it off this machine
    afterwards — a backup on the same disk is lost with the disk.</p>
  <div class="field">
    <label for="backupPassphrase">Passphrase (optional)</label>
    <input id="backupPassphrase" type="password" autocomplete="new-password">
    <input id="backupPassphraseAgain" type="password" autocomplete="new-password"
      placeholder="Type it again" style="margin-top:8px">
    <p class="hint">Encrypts the file. Without one, anyone who has the file has
      every key to this server. A lost passphrase cannot be recovered.</p>
  </div>
  <button id="backupButton">Create backup</button>
  <p class="hint" id="backupProgress" style="display:none"></p>
  <p class="error" id="backupError" style="display:none"></p>
  <div id="backupList" style="margin-top:14px"></div>
  <p class="hint">To restore: extract the file, then run
    <code>docker compose up -d</code> in the folder it makes. The steps are
    inside it too.</p>
</div>

<h2>Replace keys</h2>
<div class="panel">
  <p>If a key or password may have leaked, replace it here. The old one stops
    working straight away, and members do not have to do anything.</p>
  <div id="rotations"></div>
</div>

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
  renderLocal(state.local);
  renderProxy(state.proxy);
  renderRotations(state.rotations);
  loadBackups();

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
    if (v.missingEndpoints && v.missingEndpoints.length) {
      rows.push(["Endpoints missing", v.missingEndpoints.length + " to install"]);
    }
  }
  document.getElementById("version").innerHTML = rows
    .map(([k, val]) => '<tr><td class="name">' + k + "</td><td>" + val + "</td></tr>")
    .join("");

  const needed = !v.unknown && v.needed;
  document.getElementById("upgradeBox").style.display = needed ? "block" : "none";
  document.getElementById("upgradeHint").textContent = needed
    ? "This happens by itself when the console starts. Press it if a boot-time " +
      "apply was interrupted, or left a reload undone."
    : "";
}

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

/// Shown only where this stack has no Caddy of its own. Without the routing an
/// operator gets messages working and calls silently failing, because
/// signalling is four paths on the same host and nothing says so anywhere else.
function renderProxy(proxy) {
  const section = document.getElementById("proxySection");
  if (!proxy) { section.style.display = "none"; return; }
  section.style.display = "block";

  const rows = [
    ["Signalling", proxy.signallingUpstream, proxy.signallingPaths.join("  ")],
    ["Everything else", proxy.apiUpstream, "all other paths"],
    [
      "Voice media",
      "UDP " + proxy.mediaUdpPort + "  ·  TCP " + proxy.mediaTcpPort,
      "straight to the host, not through your proxy — open these on the firewall",
    ],
  ];
  document.getElementById("proxyUpstreams").innerHTML =
    '<table>' + rows.map(([name, upstream, paths]) =>
      '<tr><td class="name">' + name + '</td><td><span class="mono">' +
      escapeHtml(upstream) + '</span><div class="hint">' + escapeHtml(paths) +
      '</div></td></tr>'
    ).join("") + '</table>';

  document.getElementById("proxyCaddyfile").textContent = proxy.caddyfile;
}

document.getElementById("copyCaddyfile").addEventListener("click", async (event) => {
  await navigator.clipboard.writeText(
    document.getElementById("proxyCaddyfile").textContent,
  );
  event.target.textContent = "Copied";
  setTimeout(() => (event.target.textContent = "Copy"), 1500);
});

/// Drawn from /api/status on every refresh, so a switch thrown from another
/// tab shows up here rather than leaving two dashboards disagreeing.
// Most likely to be needed first, so first. Each says what it costs the people
// on the server, because that is the thing an operator has to weigh.
const ROTATIONS = [
  {
    kind: "signing",
    title: "Signing keys",
    cost: "Use this if a key has leaked. Everyone is signed out and signed " +
      "straight back in, without noticing.",
    confirm: "Replace the signing keys? Everyone is signed out and signed " +
      "straight back in.",
  },
  {
    kind: "livekit",
    title: "Voice credentials",
    cost: "Calls in progress drop and rejoin by themselves in under a minute.",
    confirm: "Replace the voice credentials? Calls in progress will drop and " +
      "rejoin by themselves in under a minute.",
  },
  {
    kind: "database",
    title: "Database password",
    cost: "The server does not answer for a few seconds while services restart.",
    confirm: "Replace the database password? The server will not answer for " +
      "a few seconds.",
  },
];

// Kept across the ten-second refresh: a rotation takes longer than that, and a
// button that snaps back to its label mid-rotation reads as one that finished.
window._rotationErrors = window._rotationErrors || new Map();

function renderRotations(rotations) {
  window._lastRotations = rotations;
  document.getElementById("rotations").innerHTML = ROTATIONS.map((rotation) => {
    const busy = window._rotating === rotation.kind;
    const when = rotations ? rotations[rotation.kind] : undefined;
    const last = when === undefined ? ""
      : when ? "Last replaced " + new Date(when).toLocaleString()
      : "Never replaced";
    const error = window._rotationErrors.get(rotation.kind);
    return '<div class="rotation"><div>' +
      '<strong>' + rotation.title + '</strong>' +
      '<p class="hint">' + rotation.cost + '</p>' +
      (last ? '<p class="hint">' + last + '</p>' : '') +
      (error ? '<p class="error">' + escapeHtml(error) + '</p>' : '') +
      '</div><button class="quiet" data-kind="' + rotation.kind + '"' +
      (window._rotating ? ' disabled' : '') + '>' +
      (busy ? "Replacing…" : "Replace") + '</button></div>';
  }).join("");
}

function formatBytes(bytes) {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit++;
  }
  return (unit === 0 ? value : value.toFixed(1)) + " " + units[unit];
}

async function loadBackups() {
  const state = await (await fetch("/api/backups")).json();
  const button = document.getElementById("backupButton");
  const progress = document.getElementById("backupProgress");
  const error = document.getElementById("backupError");

  button.disabled = !!state.running;
  button.textContent = state.running ? "Working…" : "Create backup";
  progress.style.display = state.running ? "block" : "none";
  progress.textContent = state.running ? state.running + "…" : "";
  if (!state.running && state.last && state.last.error) {
    error.textContent = state.last.error;
    error.style.display = "block";
  } else if (!window._backupRefused) {
    error.style.display = "none";
  }

  document.getElementById("backupList").innerHTML = state.files.map((file) =>
    '<div class="rotation"><div>' +
    '<strong class="mono">' + escapeHtml(file.name) + '</strong>' +
    '<p class="hint">' + formatBytes(file.bytes) + " · " +
    new Date(file.createdAt).toLocaleString() +
    (file.encrypted ? " · encrypted" : "") + '</p>' +
    '</div></div>'
  ).join("");

  // One poll at a time, however often the ten-second refresh calls this.
  clearTimeout(window._backupPoll);
  if (state.running) window._backupPoll = setTimeout(loadBackups, 2000);
}

function renderLocal(local) {
  const section = document.getElementById("localSection");
  if (!local) { section.style.display = "none"; return; }
  section.style.display = "block";

  const address = document.getElementById("localAddress");
  const port = document.getElementById("localPort");
  const addresses = document.getElementById("localAddresses");
  const button = document.getElementById("localToggle");

  document.getElementById("localSummary").textContent = local.on
    ? "Calls are on your own network. Switch back when you are done testing."
    : "Move calls onto your own network, so you can test one from a machine " +
      "here.";

  // Left alone while it is being typed into, because this runs every ten
  // seconds and overwriting a half-typed address is maddening.
  if (document.activeElement !== address && (local.on || !address.value)) {
    address.value = local.address;
  }
  if (document.activeElement !== port && (local.on || !port.value)) {
    port.value = local.port;
  }
  address.disabled = port.disabled = local.on;

  addresses.style.display = local.on ? "block" : "none";
  addresses.innerHTML = local.on
    ? [["Server URL", local.serverUrl], ["LiveKit URL", local.livekitUrl]]
      .map(([name, value]) =>
        '<div class="field"><label>' + name + '</label>' +
        '<div class="secret"><div class="mono">' + escapeHtml(value) + '</div>' +
        '<button class="quiet" data-copy-local="' + escapeHtml(value) + '">Copy</button>' +
        '</div></div>'
      ).join("")
    : "";

  button.dataset.on = local.on ? "1" : "";
  button.textContent = local.on
    ? "Switch back to " + local.home.split("://").pop()
    : "Switch voice to this network";

  for (const copy of document.querySelectorAll("[data-copy-local]")) {
    copy.addEventListener("click", async () => {
      await navigator.clipboard.writeText(copy.dataset.copyLocal);
      copy.textContent = "Copied";
      setTimeout(() => (copy.textContent = "Copy"), 1500);
    });
  }
}

document.getElementById("localToggle").addEventListener("click", async (event) => {
  const button = event.target;
  const error = document.getElementById("localError");
  const on = !button.dataset.on;
  error.style.display = "none";
  button.disabled = true;
  button.textContent = "Recreating containers…";

  const res = await fetch("/api/local-testing", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      on,
      address: document.getElementById("localAddress").value.trim(),
      port: Number(document.getElementById("localPort").value),
    }),
  });
  const body = await res.json();

  button.disabled = false;
  if (body.error) {
    // Put the label back here rather than waiting for the refresh: a button
    // still reading "Recreating containers…" beside an error looks like a
    // press that never finished.
    button.textContent = on ? "Switch voice to this network" : "Switch back";
    error.textContent = body.error;
    error.style.display = "block";
  }
  load();
});

document.getElementById("rotations").addEventListener("click", async (event) => {
  const button = event.target.closest("button[data-kind]");
  if (!button || window._rotating) return;
  const rotation = ROTATIONS.find((r) => r.kind === button.dataset.kind);
  if (!rotation || !confirm(rotation.confirm)) return;

  window._rotating = rotation.kind;
  window._rotationErrors.delete(rotation.kind);
  renderRotations(window._lastRotations);

  const res = await fetch("/api/rotate", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ kind: rotation.kind }),
  }).catch(() => null);
  // A database rotation restarts what the console talks to, so an answer that
  // never arrives is not proof it failed.
  const body = res ? await res.json().catch(() => ({})) : {
    error: "No answer from the console. It may still be finishing — reload in a minute.",
  };

  window._rotating = null;
  if (body.error) window._rotationErrors.set(rotation.kind, body.error);
  load();
});

document.getElementById("backupButton").addEventListener("click", async () => {
  const passphrase = document.getElementById("backupPassphrase");
  const again = document.getElementById("backupPassphraseAgain");
  const error = document.getElementById("backupError");
  window._backupRefused = false;

  if (passphrase.value !== again.value) {
    window._backupRefused = true;
    error.textContent = "The two passphrases do not match.";
    error.style.display = "block";
    return;
  }

  const res = await fetch("/api/backup", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ passphrase: passphrase.value }),
  });
  const body = await res.json().catch(() => ({}));
  if (body.error) {
    window._backupRefused = true;
    error.textContent = body.error;
    error.style.display = "block";
    return;
  }
  passphrase.value = "";
  again.value = "";
  error.style.display = "none";
  loadBackups();
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
    <p class="hint">The one this backup was made with.</p>
  </div>
  <button type="submit" id="go">Restore</button>
</form>

<div class="panel" id="progress" style="display:none">
  <ul class="steps" id="steps"></ul>
  <p class="hint">Loading a large backup can take several minutes.</p>
</div>

<div class="panel" id="done" style="display:none">
  <h2 style="margin-top:0">Your server is back</h2>
  <p>Reload this page and sign in with the console password this server had
    before the backup.</p>
</div>

<div class="panel" id="failed" style="display:none">
  <h2 style="margin-top:0">Restore stopped</h2>
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
  document.getElementById("failed").style.display = "none";
  document.getElementById("progress").style.display = "block";

  const response = await fetch("/api/restore", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ passphrase: document.getElementById("passphrase").value }),
  });

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
    }
  }
});
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
