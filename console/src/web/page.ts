/**
 * The console's one page.
 *
 * Served as a single string with its CSS and script inline. No build step, no
 * bundler, no dependency that has to be fetched at runtime — the console has
 * to work on a machine whose whole reason for existing is that it is not yet
 * finished being set up, and a page that needs a CDN is a page that fails
 * exactly then.
 */

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
<p class="sub">Find the password with <code>docker compose logs console</code>.</p>
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

/** The setup wizard, shown while there is no .env. */
export function setupPage(): string {
  return shell(
    "Set up your Rift server",
    `<h1>Set up your Rift server</h1>
<p class="sub">Two answers. Everything else is generated.</p>

<form id="form" class="panel">
  <div class="field">
    <label for="domain">Domain</label>
    <input id="domain" name="domain" placeholder="chat.example.com" autofocus>
    <p class="hint">Must already point at this machine, with ports 80 and 443 open.
      A certificate is fetched automatically. Rift will not work over plain HTTP:
      Android blocks it, so the server would be invisible to every phone.</p>
  </div>
  <div class="field">
    <label for="email">Email for certificate notices</label>
    <input id="email" name="email" type="email" placeholder="you@example.com">
    <p class="hint">Let's Encrypt uses this to warn you before a certificate expires.</p>
  </div>
  <div class="field">
    <label for="serverName">Server name</label>
    <input id="serverName" name="serverName" placeholder="My Server">
  </div>
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
  <p class="hint">Reload this page afterwards for the dashboard.</p>
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

  const body = JSON.stringify({
    domain: document.getElementById("domain").value.trim(),
    acmeEmail: document.getElementById("email").value.trim(),
    serverName: document.getElementById("serverName").value.trim(),
  });

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

<h2>Health</h2>
<div class="panel"><table id="checks"><tr><td class="name">Loading…</td></tr></table></div>

<h2>Containers</h2>
<div class="panel"><table id="services"><tr><td class="name">Loading…</td></tr></table></div>

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

  document.getElementById("secrets").innerHTML = state.secrets.map((entry) =>
    '<div class="field"><label>' + entry.name + '</label>' +
    '<div class="secret"><div class="mono">' + entry.value + '</div></div></div>'
  ).join("");
}

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
