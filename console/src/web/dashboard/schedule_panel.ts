import { heading, resultBox } from "./help.ts";

const SCHEDULE_HELP = `
<p>The console makes a backup by itself on a schedule, into the same
  <code>backups</code> folder, and deletes the oldest ones so only the number
  you choose are kept. A new server backs up every day at 03:00 UTC and keeps
  5.</p>
<h3>Steps</h3>
<ol>
  <li><strong>Backups to keep</strong>: how many files stay in
    <code>backups/</code>. After each backup that finishes, the oldest beyond
    this number are deleted. <strong>0 turns scheduled backups off</strong>,
    and then nothing is ever deleted for you.</li>
  <li><strong>How often</strong>: every day, or every week on the day you
    pick.</li>
  <li><strong>Time</strong>: the hour it starts, in UTC. The hint underneath
    says what that is on this computer's clock. Pick an hour when few people
    use the server; they will not notice, but a quiet hour makes a smaller,
    quicker backup.</li>
  <li>Optional: tick <strong>Encrypt scheduled backups</strong> and type a
    passphrase twice. It is saved on this server so backups can be made while
    nobody is here.</li>
  <li>Press <strong>Save schedule</strong>. The line at the top of the panel
    shows when the next one starts.</li>
</ol>
<h3>What counts towards the number kept</h3>
<p>Every file in <code>backups/</code>: scheduled ones and ones you make with
  <strong>Create backup</strong>. A backup you want to keep for longer — the
  one before an update, say — should be downloaded or copied somewhere else,
  or it will be deleted in turn. The list marks the files the next backup will
  delete.</p>
<h3>Good to know</h3>
<ul>
  <li>Deleting only happens after a backup has finished. If backups start
    failing, the old ones stay.</li>
  <li>If the server was off when a backup was due, one starts a few minutes
    after it is back.</li>
  <li>A failed scheduled backup is tried again an hour later, shown in red at
    the top of this panel, and marks this tab with a red dot. The reason is
    also in <code>docker compose logs console</code>.</li>
  <li>Each backup needs free disk space of about the size of the last one.
    Keeping 5 needs roughly five times that.</li>
  <li>A backup made <em>without</em> a passphrase holds this server's
    <code>.env</code>, and the scheduled passphrase is in it. Encrypt any
    backup that leaves this machine.</li>
  <li>These settings are the <code>BACKUP_*</code> lines in
    <code>.env</code>; changes there take effect within a minute.</li>
</ul>`;

/** Scheduled backups and how many to keep. */
export function schedulePanel(): string {
  const hours = Array.from(
    { length: 24 },
    (_, hour) =>
      `<option value="${hour}">${String(hour).padStart(2, "0")}:00 UTC</option>`,
  ).join("");
  const days = [
    "Sunday",
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
  ]
    .map((day, index) => `<option value="${index}">${day}</option>`).join("");

  return `
${heading("Scheduled backups", "schedule", SCHEDULE_HELP, "/backups/#schedule")}
<div class="panel">
  <p id="scheduleSummary">Loading…</p>
  <div class="fields">
    <div class="field">
      <label for="scheduleKeep">Backups to keep</label>
      <input id="scheduleKeep" type="number" min="0" max="1000" step="1" inputmode="numeric">
      <p class="hint">0 turns scheduled backups off.</p>
    </div>
    <div class="field">
      <label for="scheduleEvery">How often</label>
      <select id="scheduleEvery">
        <option value="daily">Every day</option>
        <option value="weekly">Every week</option>
      </select>
    </div>
    <div class="field" id="scheduleDayField">
      <label for="scheduleWeekday">Day</label>
      <select id="scheduleWeekday">${days}</select>
    </div>
    <div class="field">
      <label for="scheduleHour">Time</label>
      <select id="scheduleHour">${hours}</select>
      <p class="hint" id="scheduleLocal"></p>
    </div>
  </div>
  <div class="field">
    <label class="check"><input id="scheduleEncrypt" type="checkbox"> Encrypt scheduled backups</label>
    <div id="schedulePassphraseFields" hidden>
      <input id="schedulePassphrase" type="password" autocomplete="new-password"
        style="margin-top:8px">
      <input id="schedulePassphraseAgain" type="password" autocomplete="new-password"
        placeholder="Type it again" style="margin-top:8px">
      <p class="hint" id="schedulePassphraseHint">Saved on this server, so backups can
        be made while nobody is here. A lost passphrase cannot be recovered.</p>
    </div>
  </div>
  <button id="scheduleSave">Save schedule</button>
  ${resultBox("scheduleResult")}
</div>`;
}

export const SCHEDULE_SCRIPT = `
const WEEKDAYS = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];

function hourLabel(hour) {
  return String(hour).padStart(2, "0") + ":00 UTC";
}

function localTime(date) {
  return date.toLocaleString([], { weekday: "short", hour: "2-digit", minute: "2-digit" });
}

function describeSchedule(schedule) {
  if (schedule.keep === 0) {
    return "Scheduled backups are <strong>off</strong>. Nothing is deleted for you.";
  }
  return (schedule.every === "daily" ? "Every day" : "Every " + WEEKDAYS[schedule.weekday]) +
    " at " + hourLabel(schedule.hour) + (schedule.encrypted ? ", encrypted" : "") +
    ", keeping the newest " + schedule.keep + ". Next: <strong>" + nextText(schedule) +
    "</strong>.";
}

function nextText(schedule) {
  const next = escapeHtml(formatWhen(schedule.next));
  return schedule.dueNow ? "within a few minutes</strong>, as one is due, then <strong>" + next : next;
}

function renderSchedule(schedule) {
  const summary = document.getElementById("scheduleSummary");
  const last = schedule.lastScheduled;
  let html = schedule.problem
    ? '<span class="error">' + escapeHtml(schedule.problem) + "</span>"
    : describeSchedule(schedule);
  if (last && last.error) {
    html += '<br><span class="error">The last scheduled backup failed (' +
      escapeHtml(formatWhen(last.finishedAt)) + "): " + escapeHtml(last.error) +
      ". It is tried again within the hour.</span>";
  } else if (last) {
    html += "<br>Last scheduled backup: " + escapeHtml(formatWhen(last.finishedAt)) +
      (last.pruned.length ? ", deleted " + last.pruned.length + " older" : "") + ".";
  }
  if (last && last.pruneError) {
    html += '<br><span class="error">Older backups could not be deleted: ' +
      escapeHtml(last.pruneError) + "</span>";
  }
  summary.innerHTML = html;
  setBadge("backups", !!(schedule.problem || (last && (last.error || last.pruneError))));

  // Filled once, and again after saving — never while somebody is editing.
  if (window._scheduleFilled || schedule.problem) return;
  window._scheduleFilled = true;
  document.getElementById("scheduleKeep").value = schedule.keep;
  document.getElementById("scheduleEvery").value = schedule.every;
  document.getElementById("scheduleWeekday").value = schedule.weekday;
  document.getElementById("scheduleHour").value = schedule.hour;
  document.getElementById("scheduleEncrypt").checked = schedule.encrypted;
  window._scheduleEncrypted = schedule.encrypted;
  updateScheduleForm();
}

function updateScheduleForm() {
  const every = document.getElementById("scheduleEvery").value;
  const hour = Number(document.getElementById("scheduleHour").value);
  const encrypt = document.getElementById("scheduleEncrypt").checked;
  document.getElementById("scheduleDayField").hidden = every !== "weekly";
  document.getElementById("schedulePassphraseFields").hidden = !encrypt;
  document.getElementById("schedulePassphrase").placeholder = window._scheduleEncrypted
    ? "Leave empty to keep the current passphrase"
    : "Passphrase";
  const at = new Date();
  at.setUTCHours(hour, 0, 0, 0);
  document.getElementById("scheduleLocal").textContent =
    "That is " + at.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) +
    " on this computer's clock.";
}

for (const id of ["scheduleEvery", "scheduleHour", "scheduleEncrypt"]) {
  document.getElementById(id).addEventListener("change", updateScheduleForm);
}

document.getElementById("scheduleSave").addEventListener("click", async () => {
  hideResult("scheduleResult");
  const keepText = document.getElementById("scheduleKeep").value.trim();
  const passphrase = document.getElementById("schedulePassphrase");
  const again = document.getElementById("schedulePassphraseAgain");
  const encrypt = document.getElementById("scheduleEncrypt").checked;

  if (!/^\\d+$/.test(keepText)) {
    showResult("scheduleResult", "Backups to keep needs a number",
      "<p>Type a whole number: 5 keeps the newest five, 0 turns scheduled backups off.</p>", true);
    return;
  }
  if (encrypt && passphrase.value !== again.value) {
    showResult("scheduleResult", "The two passphrases do not match",
      "<p>Type the same passphrase in both boxes.</p>", true);
    return;
  }

  const keep = Number(keepText);
  const files = window._backupFiles || [];
  if (keep > 0 && files.length > keep && !confirm(
    "The next backup will delete the " + (files.length - keep + 1) + " oldest backups " +
    "in the backups folder, keeping the newest " + keep + ". Download any you want to keep first. Save?"
  )) return;

  const body = await postJson("/api/backups/schedule", {
    keep,
    every: document.getElementById("scheduleEvery").value,
    hour: Number(document.getElementById("scheduleHour").value),
    weekday: Number(document.getElementById("scheduleWeekday").value),
    encrypt,
    passphrase: passphrase.value,
  });
  if (body.error) {
    showResult("scheduleResult", "The schedule was not saved", errorBody(body.error), true);
    return;
  }
  passphrase.value = "";
  again.value = "";
  window._scheduleFilled = false;
  const schedule = body.schedule;
  showResult("scheduleResult", "Schedule saved", schedule.keep === 0
    ? "<p>Scheduled backups are off, and no backup will be deleted for you. " +
      "Create backup still works whenever you press it.</p>"
    : "<ol><li>The next backup starts <strong>" + nextText(schedule) + "</strong>" +
      (schedule.dueNow ? "" : " (" + hourLabel(schedule.hour) + ")") + ".</li>" +
      "<li>After each one finishes, backups beyond the newest " + schedule.keep +
      " are deleted, including ones made by hand.</li>" +
      (schedule.encrypted
        ? "<li>Keep the passphrase in a password manager. Scheduled backups cannot be " +
          "opened without it.</li>"
        : "<li>Scheduled backups are not encrypted. Encrypt them if the files leave this " +
          "machine, for example to cloud storage.</li>") +
      "<li>Copy backups off this machine regularly: a backup on the same disk is lost " +
      "with the disk.</li></ol>");
  loadBackups();
});
`;
