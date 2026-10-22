import { resultBox } from "./help.ts";

/**
 * The Release panel's Update: the newest release and its notes, the button,
 * and the steps as they run. What it drives is update/run.ts; the help is the
 * Release heading's, on the Overview tab.
 */
export function updatePanel(): string {
  return `<table id="updateInfo"></table>
  <div id="updateBox" hidden style="margin-top:14px">
    <div id="updateNotes"></div>
    <button id="update">Update</button>
    <p class="hint">Make a backup first. The server does not answer for a minute
      or two while services restart.</p>
  </div>
  <ul class="steps" id="steps" hidden style="margin-top:14px"></ul>
  ${resultBox("updateResult")}`;
}

/** Needs the page's STREAM_SCRIPT, for its progress list and stream reader. */
export const UPDATE_SCRIPT = `
const COMPOSE_STATES = {
  current: "This release's.",
  release: "From an older release. Update brings it up to date.",
  edited: "Has changes of your own. Update shows what differs before changing anything.",
  missing: "Not found in the project folder.",
};

/// The release the Update button names, and the one it installs.
let updateTarget = null;

/// Asked once per page load, not every ten seconds: the console asks GitHub,
/// which allows sixty requests an hour.
async function loadUpdate() {
  const res = await fetch("/api/update").catch(() => null);
  if (!res || !res.ok) return;
  const u = await res.json();
  const rows = [];
  if (u.foreignImage) {
    rows.push(["Updates", "This stack runs a console image of its own (" +
      escapeHtml(u.foreignImage) + "), so whoever builds it updates it."]);
  } else if (u.releases === null) {
    rows.push(["Newest release", "Could not check: " + escapeHtml(u.problem)]);
  } else {
    rows.push(["Newest release", u.releases.length
      ? escapeHtml(u.releases[0].version) : "This is the newest."]);
  }
  rows.push(["Compose file", COMPOSE_STATES[u.compose] || escapeHtml(u.compose)]);
  document.getElementById("updateInfo").innerHTML = rows
    .map(([k, val]) => '<tr><td class="name">' + k + "</td><td>" + val + "</td></tr>")
    .join("");

  document.getElementById("updateNotes").innerHTML = (u.releases || []).map((r) =>
    "<details><summary>What's new in " + escapeHtml(r.version) + "</summary>" +
    '<pre class="block" style="white-space:pre-wrap">' +
    escapeHtml(r.notes || "No notes.") + "</pre>" +
    (r.url ? '<p class="hint"><a href="' + escapeHtml(r.url) +
      '" target="_blank" rel="noopener">On GitHub ↗</a></p>' : "") +
    "</details>"
  ).join("");
  updateTarget = u.target;
  document.getElementById("update").textContent = "Update to " + (u.target || "");
  document.getElementById("updateBox").hidden = !u.target;
}

async function startUpdate(keepCompose) {
  if (!confirm("Update now? Make a backup first if you have not. The server will " +
    "not answer for a minute or two, and calls in progress will drop and rejoin.")) return;
  hideResult("updateResult");
  const button = document.getElementById("update");
  button.disabled = true;
  steps.innerHTML = "";
  seen.clear();
  steps.hidden = false;

  const res = await fetch("/api/update", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ version: updateTarget, keepCompose }),
  }).catch(() => null);
  if (res && res.status === 401) return location.reload();

  let outcome = null;
  let error = res ? null : "No answer from the console.";
  if (res && !res.ok) {
    error = (await res.json().catch(() => ({}))).error || "The update did not start.";
  } else if (res) {
    await readStream(res, (event) => {
      if (event.step) mark(event.step, event.done);
      if (event.outcome) outcome = event.outcome;
      if (event.error) error = event.error;
    }).catch(() => { error = error || "The console stopped answering mid-update."; });
  }
  button.disabled = false;

  if (error) {
    showResult("updateResult", "Nothing was updated", errorBody(error,
      "The full reason is in <code>docker compose logs console</code>."), true);
  } else if (outcome && outcome.kind === "edited") {
    showResult("updateResult", "Your compose file has changes of your own",
      "<p>Nothing was changed. Release " + escapeHtml(outcome.version) +
      "'s file is at <code>" + escapeHtml(outcome.newFile) + "</code>. What " +
      "differs, from yours (-) to the new one (+):</p>" +
      '<pre class="block">' + escapeHtml(outcome.diff) + "</pre>" +
      "<p>Either replace yours with it (<code>mv docker-compose.yml.new " +
      "docker-compose.yml</code>) and press Update again, or bring its changes " +
      "into yours and then:</p>" +
      '<button id="keepCompose">Update, keeping my file</button>', true);
    document.getElementById("keepCompose").addEventListener("click", () =>
      startUpdate(true));
  } else if (outcome && outcome.kind === "current") {
    showResult("updateResult", "Already up to date", "<p>Nothing to do.</p>");
    loadUpdate();
  } else if (outcome) {
    showResult("updateResult", "Restarting on " + escapeHtml(outcome.version),
      (outcome.warning ? errorBody("Not every service started cleanly: " +
        outcome.warning, "") : "") +
      "<p>The console is replacing itself and then finishes the update. This " +
      "page reloads when it is back; sign in again.</p>");
    waitForConsole(outcome.version);
  }
}

/// Reload once the new console answers. Sessions do not survive a restart,
/// so a 401 is the new console as surely as its version is.
async function waitForConsole(version) {
  const deadline = Date.now() + 600000;
  while (Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 3000));
    const res = await fetch("/api/version").catch(() => null);
    if (!res) continue;
    if (res.status === 401) return location.reload();
    const v = await res.json().catch(() => null);
    if (v && v.imageVersion === version) return location.reload();
  }
  showResult("updateResult", "The console has not come back",
    "<p>Run <code>docker compose logs console</code> in the project folder to see " +
    "why.</p>", true);
}

document.getElementById("update").addEventListener("click", () => startUpdate(false));
`;
