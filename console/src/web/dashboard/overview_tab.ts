import { heading, resultBox, type Tab } from "./help.ts";

const RELEASE_HELP = `
<p>Two version numbers. <strong>This image</strong> is the console you last
  pulled. <strong>This stack</strong> is the release the database and endpoints
  have been brought up to. On a healthy server they match.</p>
<h3>Update to a new release</h3>
<ol>
  <li>Make a backup from the <a href="#backups">Backups</a> tab and wait for it
    to finish.</li>
  <li>On the server, open a terminal in the folder that holds
    <code>docker-compose.yml</code>.</li>
  <li>Run <code>docker compose pull</code> to download the new images.</li>
  <li>Run <code>docker compose up -d</code>. That replaces the console, which
    then updates everything else by itself: new service versions, database
    changes and endpoints.</li>
  <li>After a minute, reload this page. Both numbers should match and Health
    should be green.</li>
</ol>
<p>Members may be disconnected for a few seconds while services restart. Their
  apps reconnect on their own.</p>
<h3>Apply this release</h3>
<p>This button appears only when something is still waiting, usually because an
  update was interrupted. Press it and wait. If it shows an error, run
  <code>docker compose logs console</code> for the full reason.</p>
<h3>Changed after running</h3>
<p>If this row appears, a database change that already ran here was edited
  afterwards, and the console will not apply anything on top of it. Official
  images never do this. Read the updating guide before changing anything.</p>`;

const HEALTH_HELP = `
<p>Checks for problems that leave every container running but quietly break
  something. Each row says what it found.</p>
<ul>
  <li><span class="dot ok"></span>Fine.</li>
  <li><span class="dot warn"></span>Worth a look soon.</li>
  <li><span class="dot fail"></span>Needs action now.</li>
  <li><span class="dot unknown"></span>The check could not run — usually the
    database is still starting. Wait a minute.</li>
</ul>
<h3>What each check means</h3>
<ul>
  <li><strong>Schema up to date</strong> — the database has every change this
    release needs. If not, press <strong>Apply this release</strong> above.</li>
  <li><strong>Realtime limits raised</strong> — live updates can keep up with a
    busy server. If not, messages start arriving late or not at all once a
    couple of dozen people are active.</li>
  <li><strong>Every table has row-level security</strong> — nothing in the
    database is open to outsiders. If this is ever red, act immediately.</li>
  <li><strong>Cleanup jobs scheduled</strong> — expired invites, old messages
    and orphaned attachments are cleared out. If not, they pile up.</li>
</ul>`;

const CONTAINERS_HELP = `
<p>Every container in the stack, and what Docker says about it.</p>
<ul>
  <li><span class="dot ok"></span>Running.</li>
  <li><span class="dot warn"></span>Starting. Normal for up to a minute after a
    start or restart.</li>
  <li><span class="dot fail"></span>Stopped, restarting over and over, or
    failing its health check.</li>
</ul>
<h3>If a container stays red</h3>
<ol>
  <li>Press <strong>Restart the stack</strong> below and wait a minute.</li>
  <li>Still red? In the folder with <code>docker-compose.yml</code>, run
    <code>docker compose logs --tail 100 &lt;service&gt;</code>. The service is
    the container name without <code>rift-</code>: <code>rift-db</code> is
    <code>db</code>, <code>realtime-dev.rift-realtime</code> is
    <code>realtime</code>.</li>
  <li>The last lines usually say what is wrong. The troubleshooting guide covers
    the common ones.</li>
</ol>
<p>LiveKit has no health check, so it only ever shows as running.</p>`;

const RESTART_HELP = `
<p>Starts any container that has stopped, moves any service onto the version
  the compose file names, and restarts the rest. It does not delete anything or
  change any setting.</p>
<h3>When to use it</h3>
<ul>
  <li>A container is red and stays red.</li>
  <li>Something stopped working in the app and Health does not say why.</li>
</ul>
<h3>What members notice</h3>
<p>For up to a minute the server does not answer. Apps show that they are
  reconnecting and come back on their own. Calls in progress drop and
  rejoin.</p>
<h3>Changed something in .env by hand?</h3>
<p>A restart does not pick it up: containers read <code>.env</code> only when
  they are created. Recreate the one service that uses the setting:</p>
<p><code>docker compose --profile full up -d --force-recreate --no-deps &lt;service&gt;</code></p>
<p>The console password is the exception. It is read at every sign-in, so a new
  <code>CONSOLE_PASSWORD</code> works straight away.</p>`;

/** Release, health, containers and the restart button. */
export function overviewTab(): Tab {
  return {
    id: "overview",
    label: "Overview",
    html: `
<p class="intro">How the server is doing. A red dot on this tab means something
  here needs attention.</p>

${heading("Release", "release", RELEASE_HELP, "/updating/")}
<div class="panel">
  <table id="version"><tr><td class="name">Loading…</td></tr></table>
  <div id="upgradeBox" hidden style="margin-top:14px">
    <button id="applyUpgrade">Apply this release</button>
    <p class="hint">This happens by itself when the console starts. Press it if
      that was interrupted, or left a reload undone.</p>
  </div>
  ${resultBox("upgradeResult")}
</div>

${heading("Health", "health", HEALTH_HELP, "/console/#health")}
<div class="panel"><table id="checks"><tr><td class="name">Loading…</td></tr></table></div>

${heading("Containers", "containers", CONTAINERS_HELP, "/console/#containers")}
<div class="panel"><table id="services"><tr><td class="name">Loading…</td></tr></table></div>

${heading("Restart the stack", "restart", RESTART_HELP, "/console/#restart")}
<div class="panel">
  <button class="quiet" id="restart">Restart the stack</button>
  <p class="hint">Starts anything that has stopped, moves any service onto the
    version the compose file names, and restarts the rest. The server does not
    answer for up to a minute.</p>
  ${resultBox("restartResult")}
</div>`,
    script: OVERVIEW_SCRIPT,
  };
}

const OVERVIEW_SCRIPT = `
function renderHealth(state) {
  document.getElementById("checks").innerHTML = state.checks.map((check) =>
    '<tr><td class="name"><span class="dot ' + check.level + '"></span>' +
    escapeHtml(check.name) + "</td><td>" + escapeHtml(check.detail) + "</td></tr>"
  ).join("") || '<tr><td class="name">No checks ran.</td></tr>';

  let broken = state.checks.some((check) => check.level === "fail");
  document.getElementById("services").innerHTML = state.services.map((service) => {
    const level = service.health === "unhealthy" ? "fail"
      : service.state === "running" ? (service.health === "starting" ? "warn" : "ok")
      : "fail";
    if (level === "fail") broken = true;
    // Compose says "(healthy)" only for a service that defines a healthcheck,
    // so one that does not came out as a bare "Up 14 minutes" in a column
    // where every sibling ended in a word — which reads as the word having
    // gone missing rather than as there being nothing to report.
    const status = service.state === "running" && !service.health
      ? service.status + " (no health check)"
      : service.status;
    return '<tr><td class="name"><span class="dot ' + level + '"></span>' +
      escapeHtml(service.name) + "</td><td>" + escapeHtml(status) + "</td></tr>";
  }).join("") || '<tr><td class="name">Nothing is running.</td></tr>';
  setBadge("overview", broken);
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
  document.getElementById("upgradeBox").hidden = v.unknown || !v.needed;
}

document.getElementById("applyUpgrade").addEventListener("click", async (event) => {
  const button = event.target;
  hideResult("upgradeResult");
  button.disabled = true;
  button.textContent = "Applying… (this can take a few minutes)";

  const body = await postJson("/api/upgrade");

  button.disabled = false;
  button.textContent = "Apply this release";
  if (body.error) {
    showResult("upgradeResult", "The release was not fully applied", errorBody(body.error,
      "Check that every container is green, then press the button again. " +
      "The full reason is in <code>docker compose logs console</code>."), true);
  } else {
    const done = [];
    done.push("<li>This stack is now on " + escapeHtml(body.version) + ".</li>");
    if (body.migrationsApplied && body.migrationsApplied.length) {
      done.push("<li>" + body.migrationsApplied.length + " database changes applied.</li>");
    }
    if (body.installed) done.push("<li>" + body.installed + " endpoints installed.</li>");
    if (body.endpointsRestarted === false) {
      done.push("<li>Endpoints were not reloaded, because the stack had not settled. " +
        "Once every container is green, press <strong>Restart the stack</strong>.</li>");
    }
    showResult("upgradeResult", "Release applied", "<ul>" + done.join("") + "</ul>");
  }
  load();
});

document.getElementById("restart").addEventListener("click", async (event) => {
  const button = event.target;
  if (!confirm("Restart the stack? The server will not answer for up to a minute, " +
    "and calls in progress will drop and rejoin.")) return;
  hideResult("restartResult");
  button.disabled = true;
  button.textContent = "Restarting…";

  const body = await postJson("/api/restart");

  button.disabled = false;
  button.textContent = "Restart the stack";
  if (body.error || body.ok === false) {
    showResult("restartResult", "The restart did not finish", errorBody(body.error || "",
      "In the folder with <code>docker-compose.yml</code>, run " +
      "<code>docker compose --profile full ps</code> to see which container failed, then " +
      "<code>docker compose logs --tail 100 &lt;service&gt;</code> for why."), true);
  } else {
    showResult("restartResult", "Stack restarted",
      "<p>Containers can show amber for up to a minute while they start. If one is " +
      "still red after that, open the <strong>i</strong> beside Containers.</p>");
  }
  load();
});
`;
