import { assert, assertEquals } from "jsr:@std/assert@1";
import { composeState, knownHashes, lineDiff, sha256 } from "./compose_file.ts";

const root = new URL("../../../", import.meta.url);

Deno.test("the compose file names the console this release builds", async () => {
  // The image carries this file, and an update writes it in place of the
  // operator's: naming any other console would bring that one back.
  const compose = await Deno.readTextFile(new URL("docker-compose.yml", root));
  const version = (await Deno.readTextFile(new URL("VERSION", root))).trim();
  const named = /ghcr\.io\/awais-amjed\/rift-console:([^}\s]+)/.exec(compose);
  assertEquals(named?.[1], version);
});

Deno.test("a file is replaced only when it is a published version", async () => {
  const old = "services: {}\n";
  const wanted = "services:\n  console: {}\n";
  const known = new Set([await sha256(old), await sha256(wanted)]);

  assertEquals(await composeState(null, wanted, known), "missing");
  assertEquals(await composeState(wanted, wanted, known), "current");
  assertEquals(await composeState(old, wanted, known), "release");
  // One changed line, a comment even, is the operator's.
  assertEquals(await composeState(old + "# mine\n", wanted, known), "edited");
});

Deno.test("the list of published versions skips its comment", () => {
  const hash = "a".repeat(64);
  assertEquals(
    knownHashes(`# heading\n${hash}\n\nnot-a-hash\n${hash}  -\n`),
    new Set([hash]),
  );
});

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
