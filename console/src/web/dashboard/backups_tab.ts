import { heading, resultBox, type Tab } from "./help.ts";
import { SCHEDULE_SCRIPT, schedulePanel } from "./schedule_panel.ts";

const BACKUP_HELP = `
<h3>What a backup holds</h3>
<ul>
  <li>The database: servers, members, channels, roles and messages. Messages
    stay end-to-end encrypted inside it.</li>
  <li>Every attachment people have uploaded.</li>
  <li><code>.env</code>: every key and password this server uses, including the
    console password.</li>
  <li>The compose file, and <code>RESTORE.txt</code> with the restore
    steps.</li>
</ul>
<p>The server keeps running while a backup is made. A small server takes
  seconds; many attachments take longer.</p>
<h3>Steps</h3>
<ol>
  <li>Optional: type a passphrase, twice. See below for when to use one.</li>
  <li>Press <strong>Create backup</strong>. Progress shows under the button,
    and you can use other tabs meanwhile.</li>
  <li>When it finishes, the file appears in the list. It is in the
    <code>backups</code> folder next to <code>docker-compose.yml</code>.</li>
  <li>Copy the file off this machine. A backup on the same disk is lost with
    the disk. The quickest way is its <strong>Download</strong> button.</li>
</ol>
<h3>Passphrase</h3>
<p>Without one, anyone who gets the file has every key to this server. With
  one, the file is encrypted and useless without it. Use one whenever the file
  will be kept anywhere other people or services can reach: cloud storage, a
  shared drive, email.</p>
<p><strong>A lost passphrase cannot be recovered</strong>, and nobody can open
  the backup without it. Keep it in a password manager.</p>
<h3>Copy it off this machine</h3>
<p><strong>Download:</strong> press <strong>Download</strong> beside the file.
  Your browser saves it to this computer's Downloads folder; the copy in
  <code>backups/</code> stays where it is. The download travels through the
  browser and your SSH tunnel, so it stops if either closes — for a file of
  several gigabytes, scp is more reliable.</p>
<p><strong>scp:</strong> from your own computer — this works in a Linux or
  macOS terminal and in Windows PowerShell:</p>
<p><code>scp you@your-server:/path/to/rift/backups/FILE.tar.gz .</code></p>
<p>WinSCP and FileZilla (SFTP) do the same in a window. If the copy is refused,
  the file belongs to root: on the server run
  <code>sudo chown $USER backups/*</code> first.</p>
<h3>How often</h3>
<p>Scheduled backups already run by themselves (see <strong>Scheduled
  backups</strong> below). Make one by hand as well before every update and
  after replacing keys.</p>
<h3>Old backups</h3>
<p>Only the newest few are kept — 5 unless you change it under Scheduled
  backups — and that includes backups made here. When a new one would delete
  an old one, a yellow note under the button names it. Download a backup you
  want to keep for longer. To delete one yourself, press
  <strong>Delete</strong> beside it in the list.</p>`;

const RESTORE_HELP = `
<p>Restoring builds this server again from a backup file, on a machine that is
  not already running it — a new server, or this one after a fresh install.</p>
<ol>
  <li>Install Docker on the machine.</li>
  <li>Copy the backup file there and extract it:
    <code>tar -xzf FILE.tar.gz</code>. This works on Linux, macOS and Windows 10
    or later. 7-Zip works too, in two steps (.gz, then .tar).</li>
  <li>Open a terminal in the folder it makes and run
    <code>docker compose up -d</code>.</li>
  <li><strong>Without a passphrase</strong>, the console restores it by itself.
    Follow along with <code>docker compose logs -f console</code> until it says
    the backup is restored.<br>
    <strong>With a passphrase</strong>, open the console (usually
    <code>http://localhost:8080</code>) and type it.</li>
  <li>Sign in to the console with the password the server had when the backup
    was made.</li>
  <li>If it is a new machine, point your domain's DNS at it and open the same
    ports (see the <a href="#network">Network</a> tab). The server must keep
    the address it had.</li>
  <li>Open the app and check that messages, attachments and a call work.</li>
</ol>
<p>On a machine where this server already runs, the console finds the existing
  database and restores nothing. The docs explain how to clear it first.</p>`;

/** Making backups, the files already made, and how to restore one. */
export function backupsTab(): Tab {
  return {
    id: "backups",
    label: "Backups",
    html: `
<p class="intro">Everything needed to bring this server back, in one file.</p>

${heading("Create a backup", "backup", BACKUP_HELP, "/backups/#dashboard")}
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
  <p class="hint" id="backupProgress" hidden></p>
  <p class="warn" id="backupPruneHint" hidden></p>
  ${resultBox("backupResult")}
</div>

${schedulePanel()}

<h2>Backups on this machine</h2>
<div class="panel"><div id="backupList"><p class="hint" style="margin:0">Loading…</p></div>
  ${resultBox("listResult")}</div>

${heading("Restore a backup", "restore", RESTORE_HELP, "/backups/#restore")}
<div class="panel">
  <p style="margin:0">Extract the file on the machine you are restoring to, then
    run <code>docker compose up -d</code> in the folder it makes. Press the
    <strong>i</strong> above for every step. The steps are also inside the
    file, in <code>RESTORE.txt</code>.</p>
</div>`,
    script: BACKUPS_SCRIPT + SCHEDULE_SCRIPT,
  };
}

const BACKUPS_SCRIPT = `
async function loadBackups() {
  const state = await (await fetch("/api/backups")).json();
  const button = document.getElementById("backupButton");
  const progress = document.getElementById("backupProgress");

  button.disabled = !!state.running;
  button.textContent = state.running ? "Working…" : "Create backup";
  progress.hidden = !state.running;
  progress.textContent = state.running ? state.running + "…" : "";

  // Reported once, by the page that watched it run — a failure from last week
  // is not news every time the page loads.
  if (state.running) {
    window._backupWatched = true;
  } else if (window._backupWatched && state.last) {
    window._backupWatched = false;
    reportBackup(state.last);
  }

  window._backupFiles = state.files;
  renderSchedule(state.schedule);

  // The next backup keeps itself and keep − 1 of these, so everything from
  // index keep − 1 on goes when it finishes.
  const keep = state.schedule.problem ? 0 : state.schedule.keep;
  const doomed = keep > 0 ? state.files.slice(keep - 1) : [];
  const hint = document.getElementById("backupPruneHint");
  hint.hidden = doomed.length === 0 || !!state.running;
  hint.textContent = doomed.length === 0 ? "" : "Keeping the newest " + keep +
    ": the next backup deletes " + doomed.map((file) => file.name).join(", ") +
    ". Download " + (doomed.length === 1 ? "it" : "them") + " first to keep a copy.";

  document.getElementById("backupList").innerHTML = state.files.map((file, index) =>
    '<div class="rotation"><div>' +
    '<strong class="mono">' + escapeHtml(file.name) + "</strong>" +
    '<p class="hint">' + formatBytes(file.bytes) + " · " +
    new Date(file.createdAt).toLocaleString() +
    (file.encrypted ? " · encrypted" : " · not encrypted") +
    (keep > 0 && index >= keep - 1
      ? ' · <span class="doomed">deleted by the next backup</span>'
      : "") + "</p>" +
    '</div><div class="actions">' + downloadLink(file.name) +
    '<button type="button" class="quiet small" data-delete="' + escapeHtml(file.name) +
    '">Delete</button></div></div>'
  ).join("") || '<p class="hint" style="margin:0">No backups yet.</p>';

  // One poll at a time, however often the ten-second refresh calls this.
  clearTimeout(window._backupPoll);
  if (state.running) window._backupPoll = setTimeout(loadBackups, 2000);
}

function downloadLink(name) {
  return '<a class="button" download href="/api/backups/download?name=' +
    encodeURIComponent(name) + '">Download</a>';
}

function reportBackup(last) {
  if (last.error) {
    showResult("backupResult", "The backup failed", errorBody(last.error,
      "Nothing was saved. Check the <a href='#overview'>Overview</a> tab that the " +
      "database and storage containers are green, then try again. The full reason is in " +
      "<code>docker compose logs console</code>."), true);
    return;
  }
  const file = escapeHtml(last.file || "");
  const name = (last.file || "").split("/").pop();
  showResult("backupResult", "Backup saved",
    "<p><code>" + file + "</code>" + (last.bytes ? " · " + formatBytes(last.bytes) : "") +
    "</p><p>" + downloadLink(name) + "</p><ol>" +
    "<li>Copy it off this machine: press <strong>Download</strong> to save it to this " +
    "computer's Downloads folder, or from your own computer run " +
    "<code>scp you@your-server:/path/to/rift/" + file + " .</code> — better for a large " +
    "file, because a download stops if the browser or SSH tunnel closes.</li>" +
    (window._backupEncrypted
      ? "<li>Keep the passphrase in a password manager. Without it this file cannot be opened.</li>"
      : "<li>This file is not encrypted and holds every key to the server. Keep it " +
        "somewhere private.</li>") +
    (last.pruned.length
      ? "<li>To keep the newest backups only, " + last.pruned.length + " older " +
        (last.pruned.length === 1 ? "one was" : "ones were") + " deleted: " +
        last.pruned.map((pruned) => "<code>" + escapeHtml(pruned) + "</code>").join(", ") +
        ". Change how many are kept under Scheduled backups.</li>"
      : "") +
    "<li>To restore it later, open the <strong>i</strong> beside Restore a backup.</li></ol>" +
    (last.pruneError
      ? '<p class="error">Older backups could not be deleted: ' + escapeHtml(last.pruneError) +
        "</p>"
      : ""));
}

document.getElementById("backupList").addEventListener("click", async (event) => {
  const button = event.target.closest("button[data-delete]");
  if (!button) return;
  const name = button.dataset.delete;
  hideResult("listResult");
  if (!confirm("Delete " + name + "?\\n\\nThe file is removed from this server for good. " +
    "Copies you downloaded or copied elsewhere are not affected.")) return;

  button.disabled = true;
  const body = await postJson("/api/backups/delete", { name });
  if (body.error) {
    button.disabled = false;
    showResult("listResult", "The backup was not deleted", errorBody(body.error,
      "If the file belongs to root, delete it on the server: " +
      "<code>sudo rm backups/" + escapeHtml(name) + "</code>"), true);
    return;
  }
  showResult("listResult", "Backup deleted",
    "<p><code>" + escapeHtml(name) + "</code> is gone from <code>backups/</code>.</p>");
  loadBackups();
});

document.getElementById("backupButton").addEventListener("click", async () => {
  const passphrase = document.getElementById("backupPassphrase");
  const again = document.getElementById("backupPassphraseAgain");
  hideResult("backupResult");

  if (passphrase.value !== again.value) {
    showResult("backupResult", "The two passphrases do not match",
      "<p>Type the same passphrase in both boxes, or leave both empty.</p>", true);
    return;
  }

  const body = await postJson("/api/backup", { passphrase: passphrase.value });
  if (body.error) {
    showResult("backupResult", "The backup did not start", errorBody(body.error), true);
    return;
  }
  window._backupEncrypted = passphrase.value.length > 0;
  window._backupWatched = true;
  passphrase.value = "";
  again.value = "";
  loadBackups();
});
`;
