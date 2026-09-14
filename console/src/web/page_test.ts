import { assert, assertEquals } from "jsr:@std/assert@1";
import { dashboardPage, loginPage, restorePage, setupPage } from "./page.ts";
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

/** The inline script, as the browser receives it. */
function scriptIn(html: string): string {
  const match = html.match(/<script>([\s\S]*)<\/script>/);
  return match ? match[1] : "";
}

const pages: [string, string][] = [
  ["setup", setupPage(fields, defaults)],
  ["dashboard", dashboardPage("chat.example.com")],
  ["login", loginPage(false)],
  ["restore", restorePage()],
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

Deno.test("every tab and every (i) opens something that exists", () => {
  // Found by attribute rather than getElementById, so the lookup test above
  // cannot see them: a help id typed wrong gives a button that does nothing.
  const html = dashboardPage("chat.example.com");
  const ids = new Set(idsIn(html));
  const tabs = [...html.matchAll(/data-tab="([^"]+)"/g)].map((m) => m[1]);
  assert(tabs.length >= 5, "the dashboard has no tabs");
  for (const tab of tabs) {
    assert(ids.has(`tab-${tab}`), `tab ${tab} has no panel`);
    assert(ids.has(`badge-${tab}`), `tab ${tab} has no badge`);
  }
  const helps = [...html.matchAll(/data-help="([^"]+)"/g)].map((m) => m[1]);
  assert(helps.length > 0, "no panel has help");
  for (const help of helps) {
    assert(ids.has(help), `(i) opens #${help}, which is not there`);
  }
});

Deno.test("every help box links to the docs", () => {
  const html = dashboardPage("chat.example.com");
  const boxes = html.split('class="help"').slice(1);
  for (const box of boxes) {
    const end = box.indexOf("</div>");
    assert(
      box.slice(0, end).includes('href="https://docs.joinrift.app/'),
      `a help box has no docs link: ${box.slice(0, 80)}`,
    );
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

/**
 * The scripts are written inside a TypeScript template literal, which eats a
 * backslash it does not recognise. `/^\w+:\/\//` reached the browser as
 * `/^w+:///` — a regex followed by a line comment, which commented out the
 * rest of the call and left the whole file a syntax error. Every panel on the
 * dashboard said "Loading…" and nothing said why.
 */
Deno.test("every page's inline script parses", () => {
  const pages: [string, string][] = [
    ["login", loginPage(false)],
    ["restore", restorePage()],
    ["restore", restorePage()],
    ["setup", setupPage(fields, defaults)],
    ["dashboard", dashboardPage("chat.example.com")],
  ];
  for (const [name, html] of pages) {
    const script = scriptIn(html);
    if (script.trim().length === 0) continue;
    try {
      new Function(script);
    } catch (error) {
      throw new Error(`The ${name} page's script does not parse: ${error}`);
    }
  }
});
