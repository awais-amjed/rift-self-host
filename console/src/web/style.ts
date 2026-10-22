import { FONT_FACES } from "./fonts.ts";

/**
 * The website's look: the app's indigo palette, Bricolage Grotesque for
 * headings, Geist for text and Geist Mono for labels and code, and a light
 * accent that carries dark text. The tokens match the website's style.css,
 * so a change there belongs here too.
 */
export const STYLE = `
${FONT_FACES}
:root {
  color-scheme: dark;
  --bg: #08080B; --bg-content: #0B0B0E; --panel: #0F0F14; --inset: #14141A;
  --raised: #1A1A21; --line: #24242D; --hairline: #1C1C24; --ghost: #2C2C36;
  --text: #F4F4F8; --dim: #C6C7CF; --muted: #9A9BA6; --faint: #8B8C96;
  --accent: #9BA3FF; --accent-bright: #B4BAFF; --accent-deep: #7B83FF;
  --ok: #34D399; --warn: #FBBF24; --fail: #F87171;
  --font-display: "Bricolage Grotesque", ui-sans-serif, system-ui, sans-serif;
  --font-text: "Geist", ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
  --font-mono: "Geist Mono", ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}
* { box-sizing: border-box; }
[hidden] { display: none !important; }
html { scrollbar-gutter: stable; }
body {
  margin: 0; background: var(--bg); color: var(--text);
  font: 15px/1.6 var(--font-text); -webkit-font-smoothing: antialiased;
}
a { color: var(--accent-bright); text-decoration: underline;
  text-decoration-color: rgba(180,186,255,0.35); text-underline-offset: 3px; }
a:hover { color: var(--text); text-decoration-color: currentColor; }
a, button { transition: color .15s ease, background-color .15s ease,
  border-color .15s ease, text-decoration-color .15s ease; }

/* No backticks in here, ever: this whole stylesheet is one template literal,
   so a backtick in a CSS comment closes it and the module stops parsing. */

/* ── Header ─────────────────────────────────────────────── */
header { border-bottom: 1px solid var(--hairline); }
.nav { max-width: 808px; margin: 0 auto; padding: 0 clamp(16px, 4vw, 24px);
  height: 60px; display: flex; align-items: center; gap: 24px; }
.brand { display: flex; align-items: center; gap: 10px; font-family: var(--font-display);
  font-weight: 700; font-size: 19px; letter-spacing: -0.02em; color: var(--text); }
.brand::after { content: "Console"; margin-left: 4px; font-family: var(--font-mono);
  font-size: 11.5px; font-weight: 500; letter-spacing: 0.06em; text-transform: uppercase;
  color: #B5B6C0; border: 1px solid var(--ghost); border-radius: 99px; padding: 2px 9px; }
.mark { width: 24px; height: 24px; flex: none; }
.nav-links { margin-left: auto; display: flex; align-items: center; gap: 20px; }
.nav-links a { color: var(--muted); font-size: 14.5px; font-weight: 500; padding: 8px 2px;
  text-decoration: none; }
.nav-links a:hover { color: var(--text); }

/* ── Page ───────────────────────────────────────────────── */
main { max-width: 808px; margin: 0 auto; padding: 44px clamp(16px, 4vw, 24px) 96px; }
/* A page whose whole content is one card sits in the middle of the window
   rather than at the top of an empty one. */
main.centred { max-width: 508px; min-height: calc(100vh - 61px); display: flex;
  flex-direction: column; justify-content: center; padding-block: 24px 64px; }
h1 { font-family: var(--font-display); font-size: clamp(30px, 5vw, 40px); line-height: 1.1;
  letter-spacing: -0.035em; font-weight: 750; margin: 0 0 10px; overflow-wrap: anywhere;
  text-wrap: balance; }
.eyebrow { margin: 0 0 12px; font-family: var(--font-mono); font-size: 12.5px;
  font-weight: 500; letter-spacing: 0.08em; text-transform: uppercase; color: var(--accent); }
h2 { font-family: var(--font-display); font-size: 21px; line-height: 1.25;
  letter-spacing: -0.02em; font-weight: 700; margin: 36px 0 12px; color: var(--text); }
p { color: var(--dim); margin: 0 0 16px; }
strong { color: var(--text); font-weight: 600; }
.sub { color: var(--muted); font-size: 16px; margin-bottom: 32px; }
.panel {
  background: var(--panel); border: 1px solid var(--line);
  border-radius: 12px; padding: 22px; margin-bottom: 16px;
}
.panel > h2:first-child { margin-top: 0; }

/* ── Fields ─────────────────────────────────────────────── */
label { display: block; font-family: var(--font-mono); font-size: 12px; font-weight: 500;
  text-transform: uppercase; letter-spacing: 0.08em; color: var(--faint); margin: 0 0 8px; }
input, select {
  width: 100%; padding: 11px 13px; background: var(--inset); color: var(--text);
  border: 1px solid var(--line); border-radius: 8px; font-size: 15px;
  font-family: inherit;
}
/* A tick box is never a field-width control. The rule above is for the things
   you type into, and a checkbox that inherits it stretches its box across the
   panel — so the browser centres the tick in the middle of the form, above a
   label it no longer looks attached to. That is what the setup page's toggles
   did for want of a class, so the base rule says it too: forgetting
   label.check now costs an uppercase label, not a checkbox adrift. */
input[type="checkbox"], input[type="radio"] {
  width: auto; padding: 0; accent-color: var(--accent);
}
input:focus, select:focus { outline: none; border-color: var(--accent-deep);
  box-shadow: 0 0 0 3px rgba(123,131,255,0.18); }
.fields { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 0 14px; }
label.check { display: flex; gap: 10px; align-items: center; text-transform: none;
  letter-spacing: 0; font: 500 15px/1.5 var(--font-text); color: var(--text);
  cursor: pointer; margin: 0; }
label.check input { width: auto; margin: 0; accent-color: var(--accent); }
.field { margin-bottom: 20px; }
.hint { font-size: 13.5px; color: var(--faint); margin: 6px 0 0; }

/* ── Buttons ────────────────────────────────────────────── */
/* Solid accent with dark text, as on the website: it passes contrast without
   the gradient the console used to have. */
button {
  background: var(--accent); color: #08080B;
  border: 1px solid transparent; border-radius: 8px; padding: 10px 20px; min-height: 42px;
  font: 600 15px/1.4 var(--font-text); cursor: pointer;
}
button:hover:not(:disabled) { background: var(--accent-bright); }
button:focus-visible, a:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
button:disabled { opacity: 0.5; cursor: default; }
button.quiet, a.button { background: transparent; color: #E4E4EA; border: 1px solid var(--ghost); }
button.quiet:hover:not(:disabled) { background: var(--inset); color: var(--text); }
button.small { padding: 7px 14px; min-height: 36px; font-size: 14px; font-weight: 500; }
a.button { display: inline-flex; align-items: center; border-radius: 8px; padding: 7px 14px;
  min-height: 36px; font-size: 14px; font-weight: 500; text-decoration: none; flex-shrink: 0; }
a.button:hover { background: var(--inset); color: var(--text); }
.choices { display: flex; flex-wrap: wrap; gap: 8px; margin: 4px 0 10px; }
.panel h3.step { font-size: 15px; font-weight: 600; margin: 24px 0 8px; color: var(--text); }
.panel > h3.step:first-child { margin-top: 0; }
/* One answer to a question, with what tells it apart under its name. */
.places { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 8px; }
button.place { background: var(--inset); color: var(--muted); border: 1px solid var(--line);
  text-align: left; font-weight: 400; font-size: 13.5px; padding: 13px 15px; }
button.place:hover:not(:disabled) { background: var(--raised); border-color: #3A3A46; }
button.place strong { display: block; color: var(--text); font-size: 14.5px;
  font-weight: 600; margin-bottom: 4px; }
button.place[aria-pressed="true"] { border-color: var(--accent-deep); background: #12132A;
  box-shadow: inset 0 0 0 1px var(--accent-deep); }

/* ── Lists of things ────────────────────────────────────── */
.rotation .actions { display: flex; gap: 8px; flex-shrink: 0; align-items: center; }
.rotation .doomed { color: var(--warn); }
.rotation { display: flex; gap: 16px; align-items: flex-start; justify-content: space-between;
  padding: 14px 0; border-top: 1px solid var(--hairline); }
.rotation:first-child { border-top: 0; padding-top: 0; }
.rotation:last-child { padding-bottom: 0; }
.rotation button { flex-shrink: 0; }
/* The text half takes the width it needs and the buttons wrap under it when
   there is not enough for both. A backup's name is a long monospace string,
   and held to half a phone it broke into three lines beside a two-line date. */
.rotation > div:first-child { min-width: 0; flex: 1 1 240px; }
.rotation .mono { overflow-wrap: anywhere; }
@media (max-width: 560px) { .rotation { flex-wrap: wrap; gap: 10px; } }
table { width: 100%; border-collapse: collapse; font-size: 14.5px; }
td { padding: 10px 0; border-bottom: 1px solid var(--hairline); vertical-align: top; }
tr:last-child td { border-bottom: 0; }
.panel > table:first-child tr:first-child td { padding-top: 0; }
td.name { color: var(--muted); width: 40%; }
.dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%;
  margin-right: 8px; vertical-align: 1px; }
.dot.ok { background: var(--ok); } .dot.warn { background: var(--warn); }
.dot.fail { background: var(--fail); } .dot.unknown { background: var(--faint); }

/* ── Code ───────────────────────────────────────────────── */
code, .mono { font-family: var(--font-mono); font-size: 13px; }
code { background: var(--inset); border: 1px solid var(--line); border-radius: 6px;
  padding: 0.08em 0.4em; color: #E4E4EA; overflow-wrap: anywhere; }
.invite {
  background: #12132A; border: 1px solid #3A3F8C;
  border-radius: 8px; padding: 14px; word-break: break-all;
  font-family: var(--font-mono); font-size: 14px; color: var(--accent-bright);
}
.secret { display: flex; gap: 8px; align-items: center; }
.secret .mono { flex: 1; background: var(--inset); border: 1px solid var(--line);
  border-radius: 8px; padding: 8px 11px; overflow-x: auto; white-space: nowrap; }
.secret .mono.masked { color: var(--faint); letter-spacing: 0.18em; user-select: none; }
.secret button { padding: 7px 12px; min-height: 36px; font-size: 13.5px; font-weight: 500; }
.block {
  font-family: var(--font-mono); font-size: 12.5px;
  line-height: 1.6; background: var(--bg-content); border: 1px solid var(--line);
  border-radius: 10px; padding: 12px 14px; margin: 0; color: var(--dim);
  white-space: pre; overflow-x: auto; max-height: 320px; overflow-y: auto;
}
/* Each line its own block, as wide as the longest, so a coloured line's
   background runs on when the box scrolls sideways. */
.diff span { display: block; width: max-content; min-width: 100%; }
.diff .add { color: var(--ok); background: rgba(52,211,153,0.09); }
.diff .del { color: var(--fail); background: rgba(248,113,113,0.09); }
.diff .hunk { color: var(--accent); }

/* ── Progress ───────────────────────────────────────────── */
.steps { list-style: none; padding: 0; margin: 0; font-size: 14.5px; }
.steps li { padding: 7px 0; color: var(--faint); }
.steps li.active { color: var(--text); }
.steps li.done { color: var(--dim); }
.steps li::before { content: "◦ "; }
.steps li.done::before { content: "✓ "; color: var(--ok); }
.steps li.active::before { content: "→ "; color: var(--accent); }
.error { color: var(--fail); white-space: pre-wrap; font-size: 14px; }
details { margin: 4px 0 20px; }
summary { cursor: pointer; color: var(--dim); font-size: 14.5px; padding: 6px 0; }
details[open] summary { margin-bottom: 10px; }

/* ── Callouts ───────────────────────────────────────────── */
/* Tinted panels, as the website's notes: never a stripe down one side. */
p.warn { display: flex; gap: 10px; font-size: 14px; color: #EBD3B4;
  background: #26180A; border: 1px solid #5E3D12;
  border-radius: 10px; padding: 12px 14px; margin: 8px 0 0; }
p.warn strong { color: #FFF3E2; }
p.warn a { color: #FFD08A; }
.help { background: #12132A; border: 1px solid #2E3270; border-radius: 12px;
  padding: 16px 18px; margin: 0 0 14px; font-size: 14.5px; color: #C9CCF0; }
.help p, .help li { color: inherit; }
.help p { margin: 0 0 10px; }
.help ol, .help ul { margin: 0 0 10px; padding-left: 20px; }
.help li { margin: 4px 0; }
.help h3 { font-size: 14.5px; font-weight: 600; margin: 16px 0 6px; color: var(--text); }
.help .more { margin: 0; font-size: 13.5px; }
.result { position: relative; background: #0B1F17; border: 1px solid #1D5A41;
  border-radius: 10px; padding: 12px 40px 12px 14px; margin: 14px 0 0; font-size: 14.5px;
  color: #C3EBD9; }
.result.bad { background: #2A1014; border-color: #6A2530; color: #F1C9CE; }
.result > strong { display: block; margin-bottom: 6px; }
.result p, .result li { color: inherit; margin: 0 0 6px; }
.result ol, .result ul { margin: 0 0 6px; padding-left: 20px; }
.result .close { position: absolute; top: 6px; right: 6px; background: none;
  color: var(--faint); padding: 2px 8px; min-height: 0; font-size: 18px; font-weight: 400; }
.result .close:hover { background: none; color: var(--text); }

/* ── Dashboard ──────────────────────────────────────────── */
/* Wraps rather than scrolls. A scrolling row hides whichever tabs do not fit,
   and on a phone that included the tab you were already on — the only thing
   saying so was a stub of its underline at the right-hand edge. There are five
   of them and they are short, so a second line on a narrow screen costs less
   than a hidden one. */
.tabs { display: flex; flex-wrap: wrap; gap: 4px; border-bottom: 1px solid var(--line);
  position: sticky; top: 0; background: rgba(8,8,11,0.88); backdrop-filter: blur(14px);
  z-index: 2; margin: 0 -4px; }
.tabs button { background: none; color: var(--muted); border: 0; border-radius: 0;
  border-bottom: 2px solid transparent; padding: 14px 12px 12px; min-height: 0;
  font-weight: 500; white-space: nowrap; }
.tabs button:hover:not(:disabled) { background: none; color: var(--text); }
.tabs button[aria-selected="true"] { color: var(--text); font-weight: 600;
  border-bottom-color: var(--accent); }
.tabs .badge { display: inline-block; width: 7px; height: 7px; border-radius: 50%;
  background: var(--fail); margin-left: 6px; vertical-align: 2px; }
.intro { font-size: 14.5px; color: var(--muted); margin: 22px 0 0; }
.head { display: flex; align-items: center; gap: 10px; margin: 36px 0 12px; }
.head h2 { margin: 0; }
button.info { width: 22px; height: 22px; min-height: 0; padding: 0; border-radius: 50%;
  flex-shrink: 0; font: italic 600 13px/20px Georgia, serif; background: var(--inset);
  color: var(--dim); border: 1px solid var(--line); }
button.info:hover:not(:disabled) { background: var(--raised); color: var(--text); }
button.info[aria-expanded="true"] { border-color: var(--accent-deep); color: var(--accent); }
`;
