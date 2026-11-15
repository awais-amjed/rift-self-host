import { assert, assertEquals } from "jsr:@std/assert@1";
import { changeFor, MAX_NOTES, noticeFor } from "./notice.ts";
import type { Release } from "./releases.ts";

function release(version: string, prerelease = false, notes = "n"): Release {
  return { version, notes, url: `https://example.test/${version}`, prerelease };
}

Deno.test("no answer from GitHub leaves what is stored", () => {
  assertEquals(noticeFor(null, "1.6.0"), { kind: "keep" });
});

Deno.test("nothing newer clears the notice", () => {
  assertEquals(noticeFor([release("1.6.0"), release("1.5.1")], "1.6.0"), {
    kind: "clear",
  });
});

Deno.test("the newest newer release is stored", () => {
  const notice = noticeFor(
    [release("1.6.1"), release("1.7.0"), release("1.5.0")],
    "1.6.0",
  );
  assertEquals(notice.kind, "set");
  if (notice.kind !== "set") return;
  assertEquals(JSON.parse(notice.value), {
    version: "1.7.0",
    url: "https://example.test/1.7.0",
    notes: "n",
  });
});

Deno.test("a beta is offered only to a console running one", () => {
  const releases = [release("1.7.0-beta.1", true)];
  assertEquals(noticeFor(releases, "1.6.0"), { kind: "clear" });
  const notice = noticeFor(releases, "1.6.1-beta.2");
  assertEquals(notice.kind, "set");
});

Deno.test("long notes are cut at a line break", () => {
  const notes = Array.from({ length: 1000 }, (_, i) => `line ${i} of the notes`).join(
    "\n",
  );
  const notice = noticeFor([release("1.7.0", false, notes)], "1.6.0");
  assert(notice.kind === "set");
  const stored = JSON.parse(notice.value).notes as string;
  assert(stored.length <= MAX_NOTES + 1, `${stored.length}`);
  assert(stored.endsWith("\n…"), stored.slice(-20));
});

Deno.test("what is stored decides the write, not what this process last wrote", () => {
  // An update cleared the row since this console wrote it: write it again.
  assertEquals(changeFor({ kind: "set", value: "x" }, null), { write: "x" });
  assertEquals(changeFor({ kind: "set", value: "x" }, "x"), null);
  assertEquals(changeFor({ kind: "set", value: "y" }, "x"), { write: "y" });
  // Somebody else wrote it: clear it all the same.
  assertEquals(changeFor({ kind: "clear" }, "x"), { write: null });
  assertEquals(changeFor({ kind: "clear" }, null), null);
  assertEquals(changeFor({ kind: "keep" }, "x"), null);
});
