import { heading, resultBox, type Tab } from "./help.ts";

const SERVERS_HELP = `
<p>A server is a community people join in the app, with its own members,
  channels, roles and invites. One machine can host several. They share its
  storage and its keys.</p>
<h3>Create a server</h3>
<ol>
  <li>Type a name under <strong>Create a server</strong>. Members will see
    it.</li>
  <li>Press <strong>Create</strong>. It takes a few seconds.</li>
  <li>An invite link appears. Copy it.</li>
  <li>In the Rift app, open the Join form and paste the link.</li>
</ol>
<p>That first link makes whoever uses it the server's
  <strong>administrator</strong>, and then stops working. Use it yourself, or
  send it privately to the person who will run the server.</p>
<h3>Invite more people</h3>
<p>Once someone is in, invite people from inside the app. Administrators can
  make links there with an expiry and a use limit.</p>
<p><strong>Create invite link</strong> here makes a link that works once and
  joins the person as an ordinary member. It is for when nobody can make one
  from the app yet.</p>
<p>Anyone who has a link can use it, so send links privately — not in a public
  post, and not in a screenshot.</p>`;

/** The servers on this stack, their invites, and the create form. */
export function serversTab(): Tab {
  return {
    id: "servers",
    label: "Servers",
    html: `
<p class="intro">The communities on this machine, and the links people use to
  join them.</p>

${heading("Servers", "servers", SERVERS_HELP, "/console/#servers")}
<div class="panel">
  <table id="servers"><tr><td class="name">Loading…</td></tr></table>
  ${resultBox("inviteResult")}
  <div class="field" style="margin:18px 0 0">
    <label for="newServer">Create a server</label>
    <div class="secret">
      <input id="newServer" placeholder="My Server" style="flex:1">
      <button id="createServer">Create</button>
    </div>
    <p class="hint">Only a name is needed. Everything else a server needs — the
      service key, the voice address and its credentials — is already here.</p>
  </div>
  <div id="newInvite" hidden>
    <h2>Administrator invite link</h2>
    <div class="secret">
      <div class="invite" id="newInviteLink" style="flex:1"></div>
      <button class="quiet" id="copyNewInvite">Copy</button>
    </div>
  </div>
  ${resultBox("serverResult")}
</div>`,
    script: SERVERS_SCRIPT,
  };
}

const SERVERS_SCRIPT = `
async function loadServers() {
  const data = await (await fetch("/api/servers")).json();
  const linkFor = (id) => (data.invites.find((i) => i.serverId === id) || {}).link;

  document.getElementById("servers").innerHTML = data.servers.map((server) => {
    const link = linkFor(server.id);
    return '<tr><td class="name">' + escapeHtml(server.name) + "</td><td>" +
      server.memberCount + " member" + (server.memberCount === 1 ? "" : "s") + " · " +
      server.channelCount + " channel" + (server.channelCount === 1 ? "" : "s") +
      '<div class="secret" style="margin-top:8px">' +
      (link
        ? '<div class="mono">' + escapeHtml(link) + "</div>" +
          '<button class="quiet" data-copy-invite="' + escapeHtml(link) + '">Copy</button>'
        : '<button class="quiet" data-invite="' + escapeHtml(server.id) + '">Create invite link</button>') +
      "</div></td></tr>";
  }).join("") || '<tr><td class="name">No servers yet. Create one below.</td></tr>';
}

document.getElementById("servers").addEventListener("click", async (event) => {
  const copy = event.target.closest("[data-copy-invite]");
  if (copy) return copyText(copy, copy.dataset.copyInvite);

  const button = event.target.closest("[data-invite]");
  if (!button) return;
  button.disabled = true;
  hideResult("inviteResult");
  const body = await postJson("/api/servers/invite", {
    serverId: button.dataset.invite,
    maxUses: 1,
  });
  if (body.link) {
    showResult("inviteResult", "Invite link created",
      "<ul><li>It works once, and joins the person as an ordinary member.</li>" +
      "<li>Press <strong>Copy</strong> beside the server and send it privately.</li>" +
      "<li>It stays listed here until someone uses it.</li></ul>");
    loadServers();
  } else {
    button.disabled = false;
    showResult("inviteResult", "No invite was created", errorBody(body.error ||
      "The console did not say why."), true);
  }
});

document.getElementById("createServer").addEventListener("click", async (event) => {
  const button = event.target;
  const input = document.getElementById("newServer");
  hideResult("serverResult");
  button.disabled = true;
  button.textContent = "Creating…";

  const body = await postJson("/api/servers/create", { name: input.value.trim() });

  button.disabled = false;
  button.textContent = "Create";
  if (body.inviteLink) {
    input.value = "";
    document.getElementById("newInvite").hidden = false;
    document.getElementById("newInviteLink").textContent = body.inviteLink;
    showResult("serverResult", "Server created",
      "<ol><li>Copy the link above.</li>" +
      "<li>Paste it into the Join form in the Rift app, or send it privately to the " +
      "person who will run this server.</li>" +
      "<li>Whoever uses it first becomes the server's administrator. After that the " +
      "link stops working.</li></ol>");
    loadServers();
  } else {
    showResult("serverResult", "The server was not created", errorBody(body.error ||
      "The console did not say why.", "Check the Overview tab that every container is " +
      "green, then try again."), true);
  }
});

document.getElementById("copyNewInvite").addEventListener("click", (event) =>
  copyText(event.target, document.getElementById("newInviteLink").textContent)
);
`;
