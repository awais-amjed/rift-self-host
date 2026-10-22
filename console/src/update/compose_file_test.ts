import { assert, assertEquals } from "jsr:@std/assert@1";
import { join } from "jsr:@std/path@1";
import {
  composeState,
  knownHashes,
  mergeCompose,
  publishedVersions,
  setAside,
  sha256,
} from "./compose_file.ts";

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

Deno.test("the image carries every published version, not only their hashes", async () => {
  // A merge needs the version an operator's file began as, and the list
  // and the folder are written together: one without the other is a release
  // made without scripts/known_compose.sh.
  const listed = knownHashes(
    await Deno.readTextFile(new URL("console/known-compose.sha256", root)),
  );
  const folder = new URL("console/known-compose/", root).pathname;
  const versions = await publishedVersions(folder);
  assertEquals(new Set(await Promise.all(versions.map(sha256))), listed);
});

/** A compose-shaped file: [lines] numbered lines, some changed. */
function file(changes: Record<number, string> = {}, extra: string[] = []): string {
  const lines = Array.from({ length: 30 }, (_, i) => changes[i] ?? `  line ${i}`);
  return [...lines, ...extra].join("\n") + "\n";
}

Deno.test("an edited file merges into a release, from the version it began as", () => {
  const older = file({ 3: "  image: console:1.0.14" });
  const began = file({ 3: "  image: console:1.0.15" });
  const release = file({ 3: "  image: console:1.1.0" }, ["  volume: storage"]);
  const mine = file({ 3: "  image: console:1.0.15", 20: "  restart: always" });

  const merged = mergeCompose(mine, release, [older, began]);
  assertEquals(merged.kind, "clean");
  if (merged.kind !== "clean") return;
  assertEquals(
    merged.text,
    file({ 3: "  image: console:1.1.0", 20: "  restart: always" }, ["  volume: storage"]),
  );
  assert(merged.diff.includes("+   image: console:1.1.0"));
  assert(!merged.diff.includes("restart"), "their own change is not shown as a change");
});

Deno.test("an edit to a line the release changed does not merge", () => {
  const began = file({ 3: "  image: console:1.0.15" });
  const release = file({ 3: "  image: console:1.1.0" });
  const mine = file({ 3: "  image: my-console:dev" });
  assertEquals(mergeCompose(mine, release, [began]), { kind: "conflict", lines: [4] });
});

Deno.test("a file unlike every published version is not merged", () => {
  const mine = Array.from({ length: 30 }, (_, i) => `mine ${i}`).join("\n");
  assertEquals(mergeCompose(mine, file(), [file()]).kind, "unknown");
  assertEquals(mergeCompose(file(), file(), []).kind, "unknown");
});

Deno.test("setting a file aside never writes over an earlier copy", async () => {
  const dir = await Deno.makeTempDir();
  try {
    await Deno.writeTextFile(join(dir, "docker-compose.yml"), "first");
    assertEquals(await setAside(dir, "1.1.1"), "docker-compose.yml.before-1.1.1");
    await Deno.writeTextFile(join(dir, "docker-compose.yml"), "second");
    assertEquals(await setAside(dir, "1.1.1"), "docker-compose.yml.before-1.1.1-2");
    assertEquals(
      await Deno.readTextFile(join(dir, "docker-compose.yml.before-1.1.1")),
      "first",
    );
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
});
