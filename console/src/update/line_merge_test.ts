import { assert, assertEquals } from "jsr:@std/assert@1";
import { changedLines, lineDiff, merge3 } from "./line_merge.ts";

Deno.test("a diff shows what changed, with the lines around it", () => {
  const before = ["a", "b", "c", "d", "e", "f", "g", "h", "i"].join("\n");
  const after = ["a", "b", "c", "d", "E", "f", "g", "h", "i", "j"].join("\n");
  assertEquals(
    lineDiff(before, after, 1),
    ["@@ line 4", "  d", "- e", "+ E", "  f", "@@ line 9", "  i", "+ j"].join("\n"),
  );
  assertEquals(lineDiff(before, before), "");
  assert(lineDiff("", "x").includes("+ x"));
});

Deno.test("a file's last newline is not a line of its own", () => {
  assertEquals(lineDiff("a\nb\n", "a\nc\n", 0), ["@@ line 2", "- b", "+ c"].join("\n"));
});

Deno.test("a merge keeps the changes each side made", () => {
  const base = "a\nb\nc\nd\ne\n";
  const ours = "a\nB\nc\nd\ne\n";
  const theirs = "a\nb\nc\nd\nE\nf\n";
  assertEquals(merge3(base, ours, theirs), { clean: true, text: "a\nB\nc\nd\nE\nf\n" });
  // Both making the same change is no conflict.
  assertEquals(merge3(base, ours, ours), { clean: true, text: ours });
  // Lines one side removed stay removed.
  assertEquals(merge3(base, "a\nc\nd\ne\n", theirs), {
    clean: true,
    text: "a\nc\nd\nE\nf\n",
  });
});

Deno.test("both sides changing the same line is a conflict, named by our line", () => {
  assertEquals(merge3("a\nb\nc\n", "a\nmine\nc\n", "a\ntheirs\nc\n"), {
    clean: false,
    conflicts: [2],
  });
  // Different lines added at the same place: no order is right.
  assertEquals(merge3("a\nb\n", "a\nx\nb\n", "a\ny\nb\n").clean, false);
});

Deno.test("changed lines count what was removed and added", () => {
  assertEquals(changedLines("a\nb\nc\n", "a\nB\nc\nd\n"), 3);
  assertEquals(changedLines("a\n", "a\n"), 0);
});
