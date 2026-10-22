/**
 * The website's three typefaces, served by the console itself.
 *
 * Not from Google Fonts or the website: the console has to look right on a
 * machine that cannot reach either, and a page that asks somebody else for
 * its fonts tells them who is running a server. Only the Latin files are
 * carried; anything else falls back to the system's own faces. All three are
 * under the SIL Open Font License, whose text sits beside the files in
 * `console/fonts/`, copied from the website's.
 */

/** The files in `console/fonts/` a page may ask for. Nothing else is read. */
const FILES = new Set([
  "bricolage-grotesque-var-latin.woff2",
  "bricolage-grotesque-var-latin-ext.woff2",
  "geist-var-latin.woff2",
  "geist-var-latin-ext.woff2",
  "geist-mono-var-latin.woff2",
  "geist-mono-var-latin-ext.woff2",
]);

const DIRECTORY = new URL("../../fonts/", import.meta.url);

const LATIN = "U+0000-00FF, U+0131, U+0152-0153, U+02BB-02BC, U+02C6, U+02DA, U+02DC, " +
  "U+0304, U+0308, U+0329, U+2000-206F, U+20AC, U+2122, U+2191, U+2193, U+2212, " +
  "U+2215, U+FEFF, U+FFFD";
const LATIN_EXT = "U+0100-02BA, U+02BD-02C5, U+02C7-02CC, U+02CE-02D7, U+02DD-02FF, " +
  "U+0304, U+0308, U+0329, U+1D00-1DBF, U+1E00-1E9F, U+1EF2-1EFF, U+2020, " +
  "U+20A0-20AB, U+20AD-20C4, U+2113, U+2C60-2C7F, U+A720-A7FF";

function face(family: string, weight: string, file: string, range: string): string {
  return `@font-face { font-family: "${family}"; font-style: normal; ` +
    `font-weight: ${weight}; font-display: swap; ` +
    `src: url(/fonts/${file}) format("woff2"); unicode-range: ${range}; }`;
}

/** The faces, for the top of the stylesheet. */
export const FONT_FACES = [
  face(
    "Bricolage Grotesque",
    "500 800",
    "bricolage-grotesque-var-latin-ext.woff2",
    LATIN_EXT,
  ),
  face("Bricolage Grotesque", "500 800", "bricolage-grotesque-var-latin.woff2", LATIN),
  face("Geist", "400 700", "geist-var-latin-ext.woff2", LATIN_EXT),
  face("Geist", "400 700", "geist-var-latin.woff2", LATIN),
  face("Geist Mono", "400 600", "geist-mono-var-latin-ext.woff2", LATIN_EXT),
  face("Geist Mono", "400 600", "geist-mono-var-latin.woff2", LATIN),
].join("\n");

/**
 * The font [path] names, or null when it names none. Answered before the
 * sign-in check, since the sign-in page uses them too. Kept for a year: a
 * font that changes gets a new file name.
 */
export async function fontResponse(path: string): Promise<Response | null> {
  const name = path.slice("/fonts/".length);
  if (!FILES.has(name)) return null;
  return new Response(await Deno.readFile(new URL(name, DIRECTORY)), {
    headers: {
      "Content-Type": "font/woff2",
      "Cache-Control": "public, max-age=31536000, immutable",
    },
  });
}
