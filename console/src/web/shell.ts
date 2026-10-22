/**
 * What every console page shares: the document around it, and the escaping
 * both halves of a page need.
 *
 * Served as a single string with its CSS and script inline. No build step, no
 * bundler, no dependency that has to be fetched at runtime — the console has
 * to work on a machine whose whole reason for existing is that it is not yet
 * finished being set up, and a page that needs a CDN is a page that fails
 * exactly then.
 */

import { STYLE } from "./style.ts";

/** The server-side half of the page's own `escapeHtml`. */
export function escapeAttribute(value: string): string {
  return value.replace(
    /[&<>"']/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!,
  );
}

/** Rift's mark, as on the website: two half-discs pulled apart. */
const MARK = '<svg class="mark" viewBox="0 0 100 100" aria-hidden="true"><defs>' +
  '<linearGradient id="markg" gradientUnits="userSpaceOnUse" x1="0" y1="0" x2="100" y2="100">' +
  '<stop offset="0" stop-color="#7B83FF"/><stop offset=".52" stop-color="#A56BFA"/>' +
  '<stop offset="1" stop-color="#EC4899"/></linearGradient></defs>' +
  '<path fill="url(#markg)" d="M46.5 10 A32 32 0 0 0 46.5 74 Z"/>' +
  '<path fill="url(#markg)" d="M53.5 26 A32 32 0 0 1 53.5 90 Z"/></svg>';

/** The mark again as the tab's icon, inline like everything else. */
const ICON = "data:image/svg+xml," +
  encodeURIComponent(
    MARK.replace('class="mark" ', 'xmlns="http://www.w3.org/2000/svg" '),
  );

/**
 * A page: [links] go in the header beside the link to the docs, and
 * [mainClass] on its `main`.
 */
export function shell(
  title: string,
  body: string,
  script = "",
  mainClass = "",
  links = "",
): string {
  return `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<meta name="theme-color" content="#08080B">
<title>${title}</title>
<link rel="icon" href="${ICON}">
<style>${STYLE}</style>
</head><body>
<header><div class="nav"><span class="brand">${MARK} Rift</span>
<nav class="nav-links"><a href="https://docs.joinrift.app/console/" target="_blank"
rel="noopener">Docs</a>${links}</nav></div></header>
<main${mainClass ? ` class="${mainClass}"` : ""}>${body}</main>
${script ? `<script>${script}</script>` : ""}
</body></html>`;
}

/**
 * The progress list and stream reader that setup and restore both drive.
 *
 * Newline-delimited JSON, streamed as each step finishes, so a five-minute
 * image pull does not look like a hang.
 */
export const STREAM_SCRIPT = `
const steps = document.getElementById("steps");
const seen = new Map();

function mark(step, done) {
  let li = seen.get(step);
  if (!li) {
    li = document.createElement("li");
    li.textContent = step;
    steps.appendChild(li);
    seen.set(step, li);
  }
  for (const other of steps.children) {
    if (other.className === "active") other.className = "done";
  }
  li.className = done ? "done" : "active";
}

async function readStream(response, onEvent) {
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";

  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split("\\n");
    buffer = lines.pop();
    for (const line of lines) {
      if (line.trim()) onEvent(JSON.parse(line));
    }
  }
}
`;
