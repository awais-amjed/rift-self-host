/** Rift's palette, matching the app's default (indigo, dark). */
export const STYLE = `
:root {
  color-scheme: dark;
  --bg: #08080B; --panel: #0D0D11; --inset: #14141A; --raised: #1A1A21;
  --text: #F4F4F8; --dim: #C6C7CF; --faint: #8B8C96;
  --line: rgba(255,255,255,0.09);
  --accent: #7B83FF; --accent-bright: #9BA3FF;
  --ok: #34D399; --warn: #FBBF24; --fail: #F87171;
}
* { box-sizing: border-box; }
[hidden] { display: none !important; }
html { scrollbar-gutter: stable; }
body {
  margin: 0; background: var(--bg); color: var(--text);
  font: 15px/1.55 ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
}
main { max-width: 760px; margin: 0 auto; padding: 48px 24px 96px; }
/* A page whose whole content is one card sits in the middle of the window
   rather than at the top of an empty one. */
main.centred { min-height: 100vh; display: flex; flex-direction: column;
  justify-content: center; padding-block: 24px; }
a { color: var(--accent-bright); }
h1 { font-size: 24px; letter-spacing: -0.02em; margin: 0 0 6px; }
h2 { font-size: 15px; margin: 32px 0 12px; color: var(--dim); font-weight: 600; }
p { color: var(--dim); margin: 0 0 16px; }
.sub { color: var(--faint); margin-bottom: 32px; }
.panel {
  background: var(--panel); border: 1px solid var(--line);
  border-radius: 12px; padding: 20px; margin-bottom: 16px;
}
label { display: block; font-size: 12px; text-transform: uppercase;
  letter-spacing: 0.06em; color: var(--faint); margin: 0 0 6px; }
input {
  width: 100%; padding: 11px 13px; background: var(--inset); color: var(--text);
  border: 1px solid var(--line); border-radius: 8px; font-size: 15px;
  font-family: inherit;
}
/* A tick box is never a field-width control. The rule above is for the things
   you type into, and a checkbox that inherits it stretches its box across the
   panel — so the browser centres the tick in the middle of the form, above a
   label it no longer looks attached to. That is what the setup page's toggles
   did for want of a class, so the base rule says it too: forgetting
   label.check now costs an uppercase label, not a checkbox adrift.

   No backticks in here, ever: this whole stylesheet is one template literal,
   so a backtick in a CSS comment closes it and the module stops parsing. */
input[type="checkbox"], input[type="radio"] {
  width: auto; padding: 0; accent-color: var(--accent);
}
select {
  width: 100%; padding: 10px 12px; background: var(--inset); color: var(--text);
  border: 1px solid var(--line); border-radius: 8px; font-size: 15px; font-family: inherit;
}
input:focus, select:focus { outline: none; border-color: var(--accent); }
.fields { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 0 14px; }
label.check { display: flex; gap: 10px; align-items: center; text-transform: none;
  letter-spacing: 0; font-size: 15px; color: var(--text); cursor: pointer; margin: 0; }
label.check input { width: auto; margin: 0; accent-color: var(--accent); }
.rotation .actions { display: flex; gap: 8px; flex-shrink: 0; align-items: center; }
button.small { padding: 8px 14px; font-size: 14px; font-weight: 500; }
.rotation .doomed { color: var(--warn); }
.field { margin-bottom: 18px; }
.hint { font-size: 13px; color: var(--faint); margin: 6px 0 0; }
.rotation { display: flex; gap: 16px; align-items: flex-start; justify-content: space-between;
  padding: 14px 0; border-top: 1px solid var(--line); }
.rotation:first-child { border-top: 0; padding-top: 0; }
.rotation:last-child { padding-bottom: 0; }
.rotation button { flex-shrink: 0; }
/* The text half takes the width it needs and the buttons wrap under it when
   there is not enough for both. A backup's name is a long monospace string,
   and held to half a phone it broke into three lines beside a two-line date. */
.rotation > div:first-child { min-width: 0; flex: 1 1 240px; }
.rotation .mono { overflow-wrap: anywhere; }
@media (max-width: 560px) { .rotation { flex-wrap: wrap; gap: 10px; } }
button {
  background: linear-gradient(135deg, var(--accent), #A56BFA); color: #fff;
  border: 0; border-radius: 8px; padding: 11px 20px; font-size: 15px;
  font-weight: 600; font-family: inherit; cursor: pointer;
}
button:disabled { opacity: 0.5; cursor: default; }
button.quiet, a.button { background: var(--inset); color: var(--dim); border: 1px solid var(--line); }
a.button { display: inline-block; border-radius: 8px; padding: 8px 14px; font-size: 14px;
  font-weight: 500; text-decoration: none; flex-shrink: 0; }
a.button:hover { color: var(--text); border-color: var(--accent); }
table { width: 100%; border-collapse: collapse; font-size: 14px; }
td { padding: 9px 0; border-bottom: 1px solid var(--line); vertical-align: top; }
tr:last-child td { border-bottom: 0; }
td.name { color: var(--dim); width: 40%; }
.dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%;
  margin-right: 8px; vertical-align: 1px; }
.dot.ok { background: var(--ok); } .dot.warn { background: var(--warn); }
.dot.fail { background: var(--fail); } .dot.unknown { background: var(--faint); }
code, .mono { font-family: ui-monospace, "SF Mono", Menlo, monospace; font-size: 13px; }
.invite {
  background: var(--inset); border: 1px solid var(--accent);
  border-radius: 8px; padding: 14px; word-break: break-all;
  font-family: ui-monospace, monospace; font-size: 14px; color: var(--accent-bright);
}
.steps { list-style: none; padding: 0; margin: 0; font-size: 14px; }
.steps li { padding: 7px 0; color: var(--faint); }
.steps li.active { color: var(--text); }
.steps li.done { color: var(--dim); }
.steps li::before { content: "◦ "; }
.steps li.done::before { content: "✓ "; color: var(--ok); }
.steps li.active::before { content: "→ "; color: var(--accent-bright); }
.error { color: var(--fail); white-space: pre-wrap; font-size: 14px; }
.secret { display: flex; gap: 8px; align-items: center; }
.secret .mono { flex: 1; background: var(--inset); border: 1px solid var(--line);
  border-radius: 6px; padding: 8px 10px; overflow-x: auto; white-space: nowrap; }
.secret .mono.masked { color: var(--faint); letter-spacing: 0.18em; user-select: none; }
.block {
  font-family: ui-monospace, "SF Mono", Menlo, monospace; font-size: 12.5px;
  line-height: 1.5; background: var(--inset); border: 1px solid var(--line);
  border-radius: 8px; padding: 12px 14px; margin: 0; color: var(--dim);
  white-space: pre; overflow-x: auto; max-height: 320px; overflow-y: auto;
}
.secret button { padding: 8px 12px; font-size: 13px; font-weight: 500; }
details { margin: 4px 0 20px; }
summary { cursor: pointer; color: var(--dim); font-size: 14px; padding: 6px 0; }
details[open] summary { margin-bottom: 10px; }
.warn { display: flex; gap: 10px; font-size: 13px; color: var(--warn);
  background: rgba(251,191,36,0.07); border: 1px solid rgba(251,191,36,0.22);
  border-radius: 8px; padding: 10px 12px; margin: 8px 0 0; }

.top { display: flex; justify-content: space-between; align-items: baseline; gap: 16px; }
.top a { font-size: 13px; color: var(--faint); }
/* Wraps rather than scrolls. A scrolling row hides whichever tabs do not fit,
   and on a phone that included the tab you were already on — the only thing
   saying so was a stub of its underline at the right-hand edge. There are five
   of them and they are short, so a second line on a narrow screen costs less
   than a hidden one. */
.tabs { display: flex; flex-wrap: wrap; gap: 2px; border-bottom: 1px solid var(--line);
  position: sticky; top: 0; background: var(--bg); z-index: 2; margin: 0 -4px; }
.tabs button { background: none; color: var(--faint); border: 0; border-radius: 0;
  border-bottom: 2px solid transparent; padding: 12px 12px 10px; font-weight: 500;
  white-space: nowrap; }
.tabs button[aria-selected="true"] { color: var(--text); border-bottom-color: var(--accent); }
.tabs .badge { display: inline-block; width: 7px; height: 7px; border-radius: 50%;
  background: var(--fail); margin-left: 6px; vertical-align: 2px; }
.intro { font-size: 14px; color: var(--faint); margin: 20px 0 0; }
.head { display: flex; align-items: center; gap: 8px; margin: 32px 0 12px; }
.head h2 { margin: 0; }
button.info { width: 22px; height: 22px; padding: 0; border-radius: 50%; flex-shrink: 0;
  font: italic 600 13px/20px Georgia, serif; background: var(--inset);
  color: var(--dim); border: 1px solid var(--line); }
button.info[aria-expanded="true"] { border-color: var(--accent); color: var(--accent-bright); }
.help { background: var(--inset); border: 1px solid var(--line);
  border-left: 3px solid var(--accent); border-radius: 8px; padding: 14px 16px;
  margin: 0 0 14px; font-size: 14px; }
.help p, .help li { color: var(--dim); }
.help p { margin: 0 0 10px; }
.help ol, .help ul { margin: 0 0 10px; padding-left: 20px; }
.help li { margin: 4px 0; }
.help h3 { font-size: 13px; margin: 14px 0 6px; color: var(--text); }
.help .more { margin: 0; font-size: 13px; }
.result { position: relative; background: rgba(52,211,153,0.07);
  border: 1px solid rgba(52,211,153,0.25); border-radius: 8px;
  padding: 12px 40px 12px 14px; margin: 14px 0 0; font-size: 14px; }
.result.bad { background: rgba(248,113,113,0.07); border-color: rgba(248,113,113,0.3); }
.result > strong { display: block; margin-bottom: 6px; }
.result p, .result li { color: var(--dim); margin: 0 0 6px; }
.result ol, .result ul { margin: 0 0 6px; padding-left: 20px; }
.result .close { position: absolute; top: 6px; right: 6px; background: none;
  color: var(--faint); padding: 2px 8px; font-size: 18px; font-weight: 400; }
`;
