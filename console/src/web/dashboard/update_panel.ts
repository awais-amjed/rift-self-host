import { resultBox } from "./help.ts";

/**
 * The Release panel's Update: the newest release and its notes, the button,
 * and the steps as they run. What it drives is update/run.ts; the help is the
 * Release heading's, on the Overview tab.
 */
export function updatePanel(): string {
  return `<table id="updateInfo"></table>
  <p class="hint" id="checkedRow" hidden style="margin-top:8px">
    <span id="checkedAgo"></span>
    <button class="small quiet" id="checkNow" type="button">Check now</button>
  </p>
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

/// A diff's lines coloured by their mark, as git colours them: what the new
/// file adds green, what it takes away red, each stretch's line number blue.
function diffHtml(diff) {
  return diff.split("\\n").map((line) => {
    const kind = line.startsWith("@@") ? "hunk"
      : line.startsWith("+") ? "add" : line.startsWith("-") ? "del" : "same";
    return '<span class="' + kind + '">' + (escapeHtml(line) || " ") + "</span>";
  }).join("");
}

/// What an edited compose file can become: merged with the release's when
/// their changes carry over, and otherwise the release's or theirs as it is.
function composeChoices(outcome) {
  const version = escapeHtml(outcome.version);
  const kept = '<p class="hint">Your file is kept as <code>docker-compose.yml.before-' +
    version + "</code>.</p>";
  const buttons = (first, second) =>
    '<div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:12px">' + first + second +
    "</div>";
  const merge = outcome.merge || { kind: "unknown" };
  if (merge.kind === "clean") {
    return "<p>Nothing was changed yet. Your changes carry over into release " + version +
      "'s file; this is what updating would change in yours:</p>" +
      '<pre class="block diff">' + diffHtml(merge.diff) + "</pre>" +
      buttons('<button data-compose="merge">Update, keeping my changes</button>',
        '<button class="quiet" data-compose="replace">Use the new file instead</button>') +
      kept;
  }
  const why = merge.kind === "conflict"
    ? "Your changes and the release's change the same lines (line " +
      merge.lines.join(", ") + " of yours), so they cannot be merged for you."
    : "Your file is too far from every published version to merge for you.";
  return "<p>Nothing was changed. " + why + " What differs, from yours (-) to release " +
    version + "'s (+):</p>" +
    '<pre class="block diff">' + diffHtml(outcome.diff) + "</pre>" +
    buttons('<button data-compose="replace">Use the new file</button>',
      '<button class="quiet" data-compose="keep">Update, keeping my file</button>') +
    '<p class="hint">Use the new file and put back what you need from yours, ' +
    "which is kept as <code>docker-compose.yml.before-" + version + "</code>. Or bring " +
    "the new file's changes into yours (it is at <code>" + escapeHtml(outcome.newFile) +
    "</code>) and keep your file.</p>";
}

/// The release the Update button names, and the one it installs.
let updateTarget = null;

/// When the console last asked GitHub, on this browser's clock.
let checkedAt = null;

/// While an update runs — from this page or any other — nothing offers to
/// start another or to check again: the steps are the panel then.
let updating = false;
let ownImage = false;

function showControls() {
  document.getElementById("updateBox").hidden = updating || !updateTarget;
  document.getElementById("checkedRow").hidden = updating || ownImage;
}

/// Asked once per page load, not every ten seconds: the console asks GitHub,
/// which allows sixty requests an hour, and remembers the answer for one.
/// [fresh] is Check now, which asks again unless it asked a minute ago.
async function loadUpdate(fresh) {
  const res = await fetch("/api/update" + (fresh ? "?fresh=1" : "")).catch(() => null);
  if (!res || !res.ok) return;
  const u = await res.json();
  checkedAt = Date.now() - u.checkedSecondsAgo * 1000;
  ownImage = !!u.foreignImage;
  showChecked();
  const rows = [];
  if (u.running && !updating) {
    // Started elsewhere: look again until it has handed over or stopped.
    rows.push(["Update", "Running now. This page shows the result once it is done."]);
    setTimeout(() => loadUpdate(), 5000);
  }
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
  updateTarget = u.running ? null : u.target;
  document.getElementById("update").textContent = "Update to " + (u.target || "");
  showControls();
}

function showChecked() {
  if (checkedAt === null) return;
  const minutes = Math.floor((Date.now() - checkedAt) / 60000);
  document.getElementById("checkedAgo").textContent = "Checked " +
    (minutes < 1 ? "just now." : minutes < 60 ? minutes + " min ago." : "over an hour ago.");
}

async function checkNow() {
  const button = document.getElementById("checkNow");
  button.disabled = true;
  button.textContent = "Checking…";
  await loadUpdate(true);
  button.disabled = false;
  button.textContent = "Check now";
}

/// [compose] is what to do with a compose file of the operator's own, once
/// they have seen what differs: replace, merge or keep.
async function startUpdate(compose) {
  if (!confirm("Update now? Make a backup first if you have not. The server will " +
    "not answer for a minute or two, and calls in progress will drop and rejoin.")) return;
  hideResult("updateResult");
  updating = true;
  showControls();
  steps.innerHTML = "";
  seen.clear();
  steps.hidden = false;

  const res = await fetch("/api/update", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ version: updateTarget, compose }),
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
  // Back unless the console is restarting, when this page reloads instead.
  updating = !error && !!outcome && outcome.kind === "restarting";
  showControls();

  if (error) {
    showResult("updateResult", "Nothing was updated", errorBody(error,
      "The full reason is in <code>docker compose logs console</code>."), true);
  } else if (outcome && outcome.kind === "edited") {
    showResult("updateResult", "Your compose file has changes of your own",
      composeChoices(outcome), true);
    for (const choice of document.querySelectorAll("#updateResult [data-compose]")) {
      choice.addEventListener("click", () => startUpdate(choice.dataset.compose));
    }
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

document.getElementById("update").addEventListener("click", () => startUpdate());
document.getElementById("checkNow").addEventListener("click", checkNow);
setInterval(showChecked, 30000);
`;
