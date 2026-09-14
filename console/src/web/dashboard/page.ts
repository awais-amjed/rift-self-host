import { escapeAttribute, shell } from "../shell.ts";
import { backupsTab } from "./backups_tab.ts";
import { COMMON_SCRIPT } from "./common_script.ts";
import { networkTab } from "./network_tab.ts";
import { overviewTab } from "./overview_tab.ts";
import { securityTab } from "./security_tab.ts";
import { serversTab } from "./servers_tab.ts";

/** The running dashboard: five tabs, refreshed every ten seconds. */
export function dashboardPage(domain: string, localTesting = false): string {
  const tabs = [overviewTab(), serversTab(), networkTab(), securityTab(), backupsTab()];

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

  const nav = tabs.map((tab) =>
    `<button type="button" role="tab" data-tab="${tab.id}" aria-controls="tab-${tab.id}">` +
    `${tab.label}<span class="badge" id="badge-${tab.id}" hidden></span></button>`
  ).join("");
  const panels = tabs.map((tab) =>
    `<section id="tab-${tab.id}" role="tabpanel" hidden>${tab.html}</section>`
  ).join("\n");

  return shell(
    "Rift console",
    // Escaped like every other operator-supplied value on this page. The
    // domain comes out of `.env`, which somebody may have written by hand.
    `<div class="top"><h1>${
      escapeAttribute(domain)
    }</h1><a href="/logout">Sign out</a></div>
<p class="sub" style="margin-bottom:20px">Rift server console. Press
  <strong>i</strong> beside any heading for step-by-step help.</p>
${banner}
<nav class="tabs" role="tablist">${nav}</nav>
${panels}`,
    `${COMMON_SCRIPT}
${tabs.map((tab) => tab.script).join("\n")}

async function load() {
  const res = await fetch("/api/status").catch(() => null);
  if (!res) return;
  if (res.status === 401) return location.reload();
  const state = await res.json();

  renderHealth(state);
  renderPorts(state.ports);
  renderProxy(state.proxy);
  renderLocal(state.local);
  renderSecrets(state.secrets);
  renderRotations(state.rotations);
  await Promise.all([loadVersion(), loadServers(), loadBackups()]);
}

load();
setInterval(load, 10000);
`,
  );
}
