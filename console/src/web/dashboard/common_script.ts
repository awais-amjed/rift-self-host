/**
 * Script every tab leans on: escaping, copying, posting, the (i) toggles, the
 * outcome boxes, and switching tabs.
 */
export const COMMON_SCRIPT = `
/// Values here are ours, but they are drawn with innerHTML and one of them is
/// operator-supplied (the domain), so they are escaped rather than trusted.
function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[c]);
}

/// A moment, spelled the same way on every tab.
///
/// toLocaleString() alone gives "9/24/2026, 8:00:00 AM": a numeric month that
/// two readers will read two ways, and seconds nobody asked for on a figure
/// that is only ever a date. A named month and no seconds, in the reader's own
/// locale and the machine's own zone — this console is about one machine, and
/// the schedule beside these times is written in UTC, so the two need telling
/// apart.
function formatWhen(value) {
  return new Date(value).toLocaleString([], {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

async function copyText(button, value) {
  await navigator.clipboard.writeText(value);
  if (!button.dataset.label) button.dataset.label = button.textContent;
  button.textContent = "Copied";
  clearTimeout(button._copied);
  button._copied = setTimeout(() => (button.textContent = button.dataset.label), 1500);
}

/// Every action goes through here, so each gets the same answer to the two
/// failures that are not the action's own: a console that is restarting, and
/// a session that has ended.
async function postJson(url, body) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {}),
  }).catch(() => null);
  if (!res) {
    return { error: "No answer from the console. It may still be finishing, or restarting — wait a minute and reload this page." };
  }
  if (res.status === 401) {
    location.reload();
    return { error: "You were signed out." };
  }
  return await res.json().catch(() => ({
    error: "The console sent back something unexpected. See docker compose logs console.",
  }));
}

/// What an action did and what to do next, in the box under its button.
/// [body] is markup the caller has already escaped.
function showResult(id, title, body, bad) {
  const box = document.getElementById(id);
  box.className = "result" + (bad ? " bad" : "");
  box.innerHTML = '<button class="close" type="button" aria-label="Dismiss">×</button>' +
    "<strong>" + title + "</strong>" + body;
  box.hidden = false;
}

function hideResult(id) {
  document.getElementById(id).hidden = true;
}

function errorBody(message, next) {
  return '<pre class="block" style="white-space:pre-wrap">' + escapeHtml(message) + "</pre>" +
    (next ? '<p style="margin-top:8px">' + next + "</p>" : "");
}

// Storage can be switched off, and a page that throws on it draws nothing.
function remembered(key) {
  try { return localStorage.getItem(key); } catch { return null; }
}
function remember(key, value) {
  try {
    if (value === null) localStorage.removeItem(key);
    else localStorage.setItem(key, value);
  } catch { /* the toggle still works, it is just not remembered */ }
}

function setHelp(button, open) {
  document.getElementById(button.dataset.help).hidden = !open;
  button.setAttribute("aria-expanded", String(open));
  remember(button.dataset.help, open ? "open" : null);
}

document.addEventListener("click", (event) => {
  const info = event.target.closest("button.info");
  if (info) setHelp(info, info.getAttribute("aria-expanded") !== "true");
  const close = event.target.closest(".result .close");
  if (close) close.parentElement.hidden = true;
});
for (const button of document.querySelectorAll("button.info")) {
  if (remembered(button.dataset.help) === "open") setHelp(button, true);
}

/// The tab lives in the address, so a reload or a shared link lands on it,
/// and a link in one tab's help can open another.
const TAB_BUTTONS = [...document.querySelectorAll(".tabs button[data-tab]")];

function showTab(name) {
  if (!TAB_BUTTONS.some((b) => b.dataset.tab === name)) name = TAB_BUTTONS[0].dataset.tab;
  for (const button of TAB_BUTTONS) {
    const on = button.dataset.tab === name;
    button.setAttribute("aria-selected", String(on));
    document.getElementById("tab-" + button.dataset.tab).hidden = !on;
  }
}

document.querySelector(".tabs").addEventListener("click", (event) => {
  const button = event.target.closest("button[data-tab]");
  if (!button) return;
  history.replaceState(null, "", "#" + button.dataset.tab);
  showTab(button.dataset.tab);
});
window.addEventListener("hashchange", () => showTab(location.hash.slice(1)));
showTab(location.hash.slice(1));

/// A red dot on a tab, for something in it that needs looking at.
function setBadge(tab, on) {
  document.getElementById("badge-" + tab).hidden = !on;
}

function formatBytes(bytes) {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit++;
  }
  return (unit === 0 ? value : value.toFixed(1)) + " " + units[unit];
}
`;
