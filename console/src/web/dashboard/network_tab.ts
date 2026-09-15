import { heading, resultBox, type Tab } from "./help.ts";

const PORTS_HELP = `
<p>People's apps connect to these ports. Open them in two places.</p>
<ol>
  <li><strong>This machine's firewall.</strong> On Ubuntu, for example:
    <code>sudo ufw allow 443/tcp</code>, and <code>sudo ufw allow 7882/udp</code>
    for a UDP row — with the port numbers from the table.</li>
  <li><strong>Your router or cloud provider.</strong> At home, forward each port
    to this machine's address on your network. On a cloud server (AWS, Hetzner,
    DigitalOcean…), add them to the firewall or security group in its control
    panel.</li>
</ol>
<h3>How to tell what is blocked</h3>
<ul>
  <li><strong>The app cannot connect at all</strong> — the web port is not
    reachable, or your domain's DNS does not point at this machine.</li>
  <li><strong>Chat works, calls never connect</strong> — call signalling is not
    reaching LiveKit.</li>
  <li><strong>A call connects but nobody hears anything</strong> — the call
    audio ports are blocked. Open both the UDP and the TCP one.</li>
</ul>
<p>Some strict networks (offices, schools, hotels) block everything but web
  traffic. People on them can chat but cannot join calls, while calls work for
  everyone else. A TURN relay on a small second server fixes that; it is
  optional, and <a href="${"https://docs.joinrift.app"}/turn/" target="_blank"
  rel="noopener">the guide</a> has every step.</p>`;

const PROXY_HELP = `
<p>This stack has no web server of its own, because it was set up to sit behind
  your own reverse proxy (nginx, Traefik, Caddy…). Your proxy handles HTTPS and
  forwards traffic to the addresses below.</p>
<h3>Set it up</h3>
<ol>
  <li>In your proxy, add a site for this server's domain, with an HTTPS
    certificate.</li>
  <li>Forward the <strong>Signalling</strong> paths to the signalling
    address.</li>
  <li>Forward <strong>everything else</strong> to the API address.</li>
  <li>Turn on WebSockets for both. Live updates and calls use them. In nginx
    that is <code>proxy_http_version 1.1;</code> plus the
    <code>Upgrade</code> and <code>Connection "upgrade"</code> headers.</li>
  <li>Reload your proxy.</li>
  <li>Open the call audio ports from <strong>Ports to open</strong>. Call audio
    never goes through your proxy.</li>
  <li>Test from the app: sign in, send a message with a picture, then start a
    call with someone.</li>
</ol>
<p>If your proxy is Caddy, copy the Caddyfile below — it already does all of
  this.</p>`;

const LOCAL_HELP = `
<p>Moves calls onto your own network while you test — for example two phones on
  the same Wi-Fi as this machine. Chat, sign-in and your domain keep working as
  normal.</p>
<h3>Turn it on</h3>
<ol>
  <li>Find this machine's address on your network: <code>hostname -I</code> on
    Linux, <code>ipconfig getifaddr en0</code> on macOS, or
    <code>ipconfig</code> on Windows (the IPv4 address). It usually starts with
    <code>192.168.</code> or <code>10.</code></li>
  <li>Type it into the first box. Leave the port unless something else on this
    machine already uses it.</li>
  <li>Press <strong>Switch voice to this network</strong>. Two containers are
    recreated, which takes about half a minute. Calls in progress drop.</li>
  <li>Start a call between devices on the same network.</li>
</ol>
<p>Invite links made while it is on point at your network, so they only work
  there.</p>
<h3>Turn it off</h3>
<p>Press <strong>Switch back</strong> when you are done. Everything returns to
  how it was, and calls work from anywhere again.</p>`;

/** Ports, the operator's own proxy, and the LAN switch. */
export function networkTab(): Tab {
  return {
    id: "network",
    label: "Network",
    html: `
<p class="intro">How people's apps reach this server: web traffic, and the
  ports calls use.</p>

${heading("Ports to open", "ports", PORTS_HELP, "/console/#network")}
<div class="panel">
  <p id="portsSummary"></p>
  <table id="ports"><tr><td class="name">Loading…</td></tr></table>
</div>

<div id="proxySection" hidden>
${heading("Your reverse proxy", "proxy", PROXY_HELP, "/console/#proxy")}
<div class="panel">
  <p>Point your proxy at both addresses below. Sending everything to the API
    is the mistake to avoid: messages work and calls fail.</p>
  <div id="proxyUpstreams"></div>
  <p class="hint">If your proxy runs in a container, attach it to this stack's
    compose network and use <code>kong:8000</code> and
    <code>livekit:7880</code> instead. Then nothing needs to be published at
    all.</p>
  <h2 style="margin-top:24px">If your proxy is Caddy</h2>
  <p>This is the stack's own Caddyfile, pointed at those addresses.</p>
  <pre class="block" id="proxyCaddyfile"></pre>
  <button class="quiet" id="copyCaddyfile" style="margin-top:10px">Copy</button>
</div>
</div>

<div id="localSection" hidden>
${heading("Local testing", "local", LOCAL_HELP, "/console/#local")}
<div class="panel">
  <p id="localSummary"></p>
  <div class="field">
    <label for="localAddress">This machine's address on your network</label>
    <div class="secret">
      <input id="localAddress" placeholder="192.168.1.6" style="flex:1">
      <input id="localPort" type="number" style="width:120px" aria-label="API port">
    </div>
    <p class="hint">The second box is the port. Leave it unless something else
      on this machine already has it. Your domain keeps working the whole
      time.</p>
  </div>
  <div id="localAddresses" hidden></div>
  <button id="localToggle">Switch voice to this network</button>
  <p class="warn"><span>For testing on your own network. While it is on, people
    outside it cannot join a call.</span></p>
  ${resultBox("localResult")}
</div>
</div>`,
    script: NETWORK_SCRIPT,
  };
}

const NETWORK_SCRIPT = `
const PORT_SUMMARIES = {
  caddy: "This stack's Caddy answers web traffic and gets the HTTPS certificate by itself.",
  proxy: "Your own reverse proxy answers web traffic, so open its ports (usually 80 and " +
    "443) rather than this stack's. Call audio still comes straight here.",
  local: "This stack was set up for local testing. It is only for your own network, so " +
    "open these on this machine's firewall only — not on your router.",
};

function renderPorts(ports) {
  const rows = ports.mode === "local"
    ? [["TCP", ports.api, "The API: sign-in, messages and attachments"],
       ["TCP", ports.signalling, "Call signalling"]]
    : ports.mode === "proxy"
    ? []
    : [["TCP", ports.http, "Web (HTTP) — used to get the certificate, then redirects to HTTPS"],
       ["TCP", ports.https, "Web (HTTPS) — the app, sign-in, messages, attachments, call signalling"]];
  rows.push(["UDP", ports.mediaUdp, "Call audio and video"]);
  rows.push(["TCP", ports.mediaTcp, "Call audio and video, for networks that block UDP"]);

  document.getElementById("portsSummary").textContent = PORT_SUMMARIES[ports.mode];
  document.getElementById("ports").innerHTML = rows.map(([protocol, port, what]) =>
    '<tr><td class="name"><span class="mono">' + escapeHtml(port) + " " + protocol +
    "</span></td><td>" + what + "</td></tr>"
  ).join("");
}

/// Shown only where this stack has no Caddy of its own. Without the routing an
/// operator gets messages working and calls silently failing, because
/// signalling is four paths on the same host and nothing says so anywhere else.
function renderProxy(proxy) {
  document.getElementById("proxySection").hidden = !proxy;
  if (!proxy) return;

  const rows = [
    ["Signalling", proxy.signallingUpstream, proxy.signallingPaths.join("  ")],
    ["Everything else", proxy.apiUpstream, "all other paths"],
    ["Voice media", "UDP " + proxy.mediaUdpPort + "  ·  TCP " + proxy.mediaTcpPort,
      "straight to this machine, not through your proxy — open these on the firewall"],
  ];
  document.getElementById("proxyUpstreams").innerHTML =
    "<table>" + rows.map(([name, upstream, paths]) =>
      '<tr><td class="name">' + name + '</td><td><span class="mono">' +
      escapeHtml(upstream) + '</span><div class="hint">' + escapeHtml(paths) +
      "</div></td></tr>"
    ).join("") + "</table>";
  document.getElementById("proxyCaddyfile").textContent = proxy.caddyfile;
}

document.getElementById("copyCaddyfile").addEventListener("click", (event) =>
  copyText(event.target, document.getElementById("proxyCaddyfile").textContent)
);

/// Drawn from /api/status on every refresh, so a switch thrown from another
/// tab shows up here rather than leaving two dashboards disagreeing.
function renderLocal(local) {
  document.getElementById("localSection").hidden = !local;
  if (!local) return;

  const address = document.getElementById("localAddress");
  const port = document.getElementById("localPort");
  const addresses = document.getElementById("localAddresses");
  const button = document.getElementById("localToggle");

  document.getElementById("localSummary").textContent = local.on
    ? "Calls are on your own network. Switch back when you are done testing."
    : "Move calls onto your own network, so you can test one from a device here.";

  // Left alone while it is being typed into, because this runs every ten
  // seconds and overwriting a half-typed address is maddening.
  if (document.activeElement !== address && (local.on || !address.value)) {
    address.value = local.address;
  }
  if (document.activeElement !== port && (local.on || !port.value)) {
    port.value = local.port;
  }
  address.disabled = port.disabled = local.on;

  addresses.hidden = !local.on;
  addresses.innerHTML = local.on
    ? [["Server URL", local.serverUrl], ["LiveKit URL", local.livekitUrl]]
      .map(([name, value]) =>
        '<div class="field"><label>' + name + "</label>" +
        '<div class="secret"><div class="mono">' + escapeHtml(value) + "</div>" +
        '<button class="quiet" data-copy-local="' + escapeHtml(value) + '">Copy</button>' +
        "</div></div>"
      ).join("")
    : "";

  window._localHome = local.home.split("://").pop();
  if (!window._localSwitching) {
    button.dataset.on = local.on ? "1" : "";
    button.textContent = local.on
      ? "Switch back to " + window._localHome
      : "Switch voice to this network";
  }
}

document.getElementById("localAddresses").addEventListener("click", (event) => {
  const copy = event.target.closest("[data-copy-local]");
  if (copy) copyText(copy, copy.dataset.copyLocal);
});

document.getElementById("localToggle").addEventListener("click", async (event) => {
  const button = event.target;
  const on = !button.dataset.on;
  const address = document.getElementById("localAddress").value.trim();
  const question = on
    ? "Switch calls to " + (address || "this network") + "? Calls in progress drop, and " +
      "until you switch back nobody outside your network can join a call."
    : "Switch calls back to " + window._localHome + "? Calls in progress drop and rejoin.";
  if (!confirm(question)) return;

  hideResult("localResult");
  window._localSwitching = true;
  button.disabled = true;
  button.textContent = "Recreating containers…";

  const body = await postJson("/api/local-testing", {
    on,
    address,
    port: Number(document.getElementById("localPort").value),
  });

  window._localSwitching = false;
  button.disabled = false;
  if (body.error) {
    // Put the label back here rather than waiting for the refresh: a button
    // still reading "Recreating containers…" beside an error looks like a
    // press that never finished.
    button.textContent = on ? "Switch voice to this network" : "Switch back";
    showResult("localResult", on ? "Calls were not switched" : "Calls were not switched back",
      errorBody(body.error, "The usual cause is a port that something else on this " +
        "machine already uses. Pick another port and try again."), true);
  } else if (on) {
    showResult("localResult", "Calls now use your network",
      "<ol><li>Start a call between devices on the same network to test.</li>" +
      "<li>Invite links made now point at this network and only work there.</li>" +
      "<li>Press <strong>Switch back</strong> when you are done.</li></ol>");
  } else {
    showResult("localResult", "Calls are back on " + escapeHtml(window._localHome),
      "<p>Calls work from anywhere again. Invite links made while testing only work on " +
      "your network, so make new ones from the Servers tab if you need them.</p>");
  }
  load();
});
`;
