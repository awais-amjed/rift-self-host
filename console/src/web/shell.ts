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

export function shell(
  title: string,
  body: string,
  script = "",
  mainClass = "",
): string {
  return `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>${title}</title>
<style>${STYLE}</style>
</head><body><main${mainClass ? ` class="${mainClass}"` : ""}>${body}</main>
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
