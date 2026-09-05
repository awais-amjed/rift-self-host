import { assert, assertEquals } from "jsr:@std/assert@1";
import { dashboardPage, loginPage, setupPage } from "./page.ts";
import { defaults, fields } from "../setup/options.ts";

/**
 * The pages are strings with their script inline, so nothing type-checks the
 * relationship between an element and the code that reaches for it. These
 * tests stand in for that.
 */

/** Every `id="..."` in [html], in document order. */
function idsIn(html: string): string[] {
  return [...html.matchAll(/\bid="([^"]+)"/g)].map((m) => m[1]);
}

/** Every `getElementById("...")` the inline script calls. */
function lookupsIn(html: string): string[] {
  return [...html.matchAll(/getElementById\("([^"]+)"\)/g)].map((m) => m[1]);
}

const pages: [string, string][] = [
  ["setup", setupPage(fields, defaults)],
  ["dashboard", dashboardPage("chat.example.com")],
  ["login", loginPage(false)],
];

Deno.test("no page gives two elements the same id", () => {
  // The bug this exists for: the setup form renders an input per option, one
  // of which is `consolePassword`, and the finished panel had a div with the
  // same id. getElementById returns the first match, so the password was
  // written as textContent onto an <input> — invisible — and the panel stayed
  // blank while the value sat in the log looking fine.
  for (const [name, html] of pages) {
    const ids = idsIn(html);
    const seen = new Set<string>();
    const duplicates: string[] = [];
    for (const id of ids) {
      // `seen.add(id)` returns the Set, which is always truthy — writing this
      // as `!seen.add(id)` gives a filter that can never match and a test that
      // can never fail. It was written that way first, and passed happily with
      // the duplicate it exists to catch sitting in front of it.
      if (seen.has(id)) duplicates.push(id);
      seen.add(id);
    }
    assertEquals(duplicates, [], `${name} page repeats: ${duplicates.join(", ")}`);
  }
});

Deno.test("every element the script reaches for exists on its page", () => {
  // The other half of the same problem: a rename that misses one call site
  // throws at the moment it runs, which for the finished panel is after a
  // five-minute setup nobody wants to repeat.
  for (const [name, html] of pages) {
    const ids = new Set(idsIn(html));
    for (const wanted of lookupsIn(html)) {
      assert(ids.has(wanted), `${name} page looks up #${wanted}, which it never renders`);
    }
  }
});

Deno.test("the setup form renders an input for every option", () => {
  const html = setupPage(fields, defaults);
  for (const field of fields) {
    assert(
      html.includes(`id="${field.key}"`),
      `no input for ${field.key}`,
    );
  }
});

Deno.test("the password field is never prefilled", () => {
  // Even when one is already known, it must not be put on screen for whoever
  // walks past — blank means "keep what is there".
  const html = setupPage(fields, { ...defaults, consolePassword: "hunter2" });
  assert(!html.includes("hunter2"), "a known password reached the form");
  assert(html.includes('id="consolePassword" name="consolePassword" type="password"'));
});

Deno.test("advanced options are behind the fold, plain ones are not", () => {
  const html = setupPage(fields, defaults);
  const advancedStart = html.indexOf("<details");
  assert(advancedStart > 0, "no advanced section");

  for (const field of fields) {
    const at = html.indexOf(`id="${field.key}"`);
    assertEquals(
      at > advancedStart,
      field.advanced,
      `${field.key} is on the wrong side of the fold`,
    );
  }
});
