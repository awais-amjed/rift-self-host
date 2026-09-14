/**
 * The dashboard's in-place instructions.
 *
 * Every panel's heading carries an (i) that opens step-by-step text above the
 * panel, ending in a link to the long version in the docs. Written into the
 * page rather than only linked, because the moment an operator needs them is
 * often the moment the docs site is the thing they cannot reach.
 */

/** Where the self-hosting docs live. */
export const DOCS = "https://docs.joinrift.app";

/** One tab: its label, its markup, and the script that drives it. */
export interface Tab {
  id: string;
  label: string;
  html: string;
  script: string;
}

/** A panel title with its (i) button, and the help it opens. */
export function heading(
  title: string,
  id: string,
  help: string,
  docsPath: string,
): string {
  return `<div class="head"><h2>${title}</h2>
<button class="info" type="button" data-help="help-${id}" aria-expanded="false"
  aria-controls="help-${id}" title="How this works">i</button></div>
<div class="help" id="help-${id}" hidden>${help}
<p class="more"><a href="${DOCS}${docsPath}" target="_blank" rel="noopener">Full guide in the docs ↗</a></p>
</div>`;
}

/** The empty box an action writes its outcome and next steps into. */
export function resultBox(id: string): string {
  return `<div class="result" id="${id}" role="status" hidden></div>`;
}
