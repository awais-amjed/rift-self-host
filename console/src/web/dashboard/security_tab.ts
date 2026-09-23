import { heading, resultBox, type Tab } from "./help.ts";

const CREDENTIALS_HELP = `
<ul>
  <li><strong>Server URL</strong> — the address people's apps connect to. Every
    member's identity on this server is tied to it, so it can never
    change.</li>
  <li><strong>LiveKit URL</strong> — where apps connect for calls. Apps are
    given it automatically.</li>
  <li><strong>Publishable key</strong> — the key apps use to reach this server.
    Members receive it when they join, so you never need to send it to anyone.
    Keep it out of screenshots anyway.</li>
</ul>
<h3>Where the other keys are</h3>
<p>Every other key and password — the database password, the signing keys, the
  voice credentials and the console password — is in <code>.env</code> beside
  <code>docker-compose.yml</code>. Anyone who can read that file controls this
  server. Keep it private, and never put it in git or a public backup.</p>
<h3>Change the console password</h3>
<ol>
  <li>Open <code>.env</code> and set <code>CONSOLE_PASSWORD=</code> to a new,
    long password.</li>
  <li>Save the file. The new password works at the next sign-in, with no
    restart.</li>
</ol>`;

const ROTATE_HELP = `
<p>Replace a key when it may have leaked: <code>.env</code> shown in a
  screenshot or a screen share, a backup left somewhere public, or someone who
  had access to this machine no longer should.</p>
<h3>Steps</h3>
<ol>
  <li>Pick the key below. Not sure which one leaked? Replace the
    <strong>signing keys</strong>.</li>
  <li>Press its <strong>Replace</strong> button and confirm. Wait until the
    button stops reading Replacing. It can take a minute.</li>
  <li>Check the <a href="#overview">Overview</a> tab: every container should be
    green.</li>
  <li>Make a new backup from the <a href="#backups">Backups</a> tab. Older
    backups still restore, but they bring the old keys back with them.</li>
  <li>Delete any copy of the old <code>.env</code> you do not control.</li>
</ol>
<p>Members do not need to do anything. What they notice is written under each
  key.</p>
<p>The publishable key cannot be replaced, because every member's app holds it.
  On its own it only lets someone reach the server as an anonymous visitor, who
  can read nothing.</p>`;

/** The server's addresses and keys, and the buttons that replace them. */
export function securityTab(): Tab {
  return {
    id: "security",
    label: "Security",
    html: `
<p class="intro">The addresses and keys this server uses, and how to replace a
  key that may have leaked.</p>

${heading("Credentials", "credentials", CREDENTIALS_HELP, "/console/#credentials")}
<div class="panel" id="secrets"></div>

${heading("Replace keys", "rotate", ROTATE_HELP, "/console/#rotate")}
<div class="panel">
  <p>If a key or password may have leaked, replace it here. The old one stops
    working straight away, and members do not have to do anything.</p>
  <div id="rotations"></div>
  ${resultBox("rotationResult")}
</div>`,
    script: SECURITY_SCRIPT,
  };
}

const SECURITY_SCRIPT = `
// Secret rows render masked and stay masked across the ten-second refresh:
// a value that reappears on its own is one that ends up on a shared screen
// because nobody noticed it come back.
window._revealed = window._revealed || new Set();

function renderSecrets(secrets) {
  window._secrets = secrets;
  const revealed = window._revealed;
  document.getElementById("secrets").innerHTML = secrets.map((entry, i) => {
    const shown = !entry.secret || revealed.has(entry.name);
    const body = shown ? escapeHtml(entry.value) : "•".repeat(28);
    return '<div class="field"><label>' + escapeHtml(entry.name) + "</label>" +
      '<div class="secret"><div class="mono' + (shown ? "" : " masked") + '">' + body + "</div>" +
      (entry.secret
        ? '<button class="quiet" data-reveal="' + i + '">' + (shown ? "Hide" : "Reveal") + "</button>"
        : "") +
      '<button class="quiet" data-copy="' + i + '">Copy</button>' +
      "</div>" +
      (shown && entry.note ? '<p class="warn">' + escapeHtml(entry.note) + "</p>" : "") +
      "</div>";
  }).join("");
}

document.getElementById("secrets").addEventListener("click", (event) => {
  const reveal = event.target.closest("[data-reveal]");
  if (reveal) {
    const entry = window._secrets[Number(reveal.dataset.reveal)];
    if (window._revealed.has(entry.name)) window._revealed.delete(entry.name);
    else window._revealed.add(entry.name);
    renderSecrets(window._secrets);
  }
  const copy = event.target.closest("[data-copy]");
  if (copy) copyText(copy, window._secrets[Number(copy.dataset.copy)].value);
});

// Most likely to be needed first, so first. Each says what it costs the people
// on the server, because that is the thing an operator has to weigh.
//
// Each button names what it replaces, too. Three buttons all reading
// "Replace" are told apart only by the heading beside them, which a tab
// order and a hurried eye both lose.
const ROTATIONS = [
  {
    kind: "signing",
    title: "Signing keys",
    action: "Replace keys",
    cost: "Use this if you are not sure what leaked. Everyone is signed out and " +
      "signed straight back in, without noticing.",
    confirm: "Replace the signing keys? Everyone is signed out and their apps sign " +
      "them straight back in. Bots sign in again by themselves.",
    after: "Everyone was signed out, and their apps signed them back in. Bots sign in " +
      "again by themselves.",
  },
  {
    kind: "livekit",
    title: "Voice credentials",
    action: "Replace credentials",
    cost: "Calls in progress drop and rejoin by themselves in under a minute.",
    confirm: "Replace the voice credentials? Calls in progress will drop and rejoin " +
      "by themselves in under a minute.",
    after: "Calls in progress dropped and are rejoining, which takes under a minute. " +
      "A new call can take about ten seconds to start while LiveKit comes back.",
  },
  {
    kind: "database",
    title: "Database password",
    action: "Replace password",
    cost: "The server does not answer for a few seconds while services restart.",
    confirm: "Replace the database password? The server will not answer for a few " +
      "seconds while services restart.",
    after: "Services restarted with the new password.",
  },
];

function renderRotations(rotations) {
  window._lastRotations = rotations;
  document.getElementById("rotations").innerHTML = ROTATIONS.map((rotation) => {
    const busy = window._rotating === rotation.kind;
    const when = rotations ? rotations[rotation.kind] : undefined;
    const last = when === undefined ? ""
      : when ? "Last replaced " + formatWhen(when)
      : "Never replaced";
    return '<div class="rotation"><div>' +
      "<strong>" + rotation.title + "</strong>" +
      '<p class="hint">' + rotation.cost + "</p>" +
      (last ? '<p class="hint">' + last + "</p>" : "") +
      '</div><button class="quiet" data-kind="' + rotation.kind + '"' +
      (window._rotating ? " disabled" : "") + ">" +
      (busy ? "Replacing…" : rotation.action) + "</button></div>";
  }).join("");
}

document.getElementById("rotations").addEventListener("click", async (event) => {
  const button = event.target.closest("button[data-kind]");
  if (!button || window._rotating) return;
  const rotation = ROTATIONS.find((r) => r.kind === button.dataset.kind);
  if (!rotation || !confirm(rotation.confirm)) return;

  hideResult("rotationResult");
  window._rotating = rotation.kind;
  renderRotations(window._lastRotations);

  // A database rotation restarts what the console talks to, so an answer that
  // never arrives is not proof it failed — postJson says so.
  const body = await postJson("/api/rotate", { kind: rotation.kind });

  window._rotating = null;
  if (body.error) {
    showResult("rotationResult", rotation.title + " not replaced", errorBody(body.error,
      "Check the <a href='#overview'>Overview</a> tab that every container is green. " +
      "The full reason is in <code>docker compose logs console</code>."), true);
  } else {
    showResult("rotationResult", rotation.title + " replaced",
      "<p>" + rotation.after + "</p><ol>" +
      "<li>Check the <a href='#overview'>Overview</a> tab: every container should be green.</li>" +
      "<li>Make a new backup from the <a href='#backups'>Backups</a> tab. Older backups " +
      "bring the old keys back if restored.</li></ol>");
  }
  load();
});
`;
