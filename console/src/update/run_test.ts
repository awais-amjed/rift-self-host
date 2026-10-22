import { assertEquals } from "jsr:@std/assert@1";
import { foreignImage, imageOf, updateTarget } from "./run.ts";
import type { Release } from "./releases.ts";

Deno.test("only a console of somebody else's is left to them", () => {
  assertEquals(foreignImage(imageOf("1.0.13")), null);
  // A compose file from before versions were named: still ours to update.
  assertEquals(foreignImage("ghcr.io/awais-amjed/rift-console:latest"), null);
  assertEquals(
    foreignImage("riftapp/rift-console:latest"),
    "riftapp/rift-console:latest",
  );
  assertEquals(
    foreignImage("ghcr.io/awais-amjed/rift-console:mine"),
    "ghcr.io/awais-amjed/rift-console:mine",
  );
  assertEquals(foreignImage(null), null);
});

Deno.test("an update goes to the newest release, or brings an old file level", () => {
  const newer: Release[] = [
    { version: "1.0.14", notes: "", url: "", prerelease: false },
    { version: "1.0.13", notes: "", url: "", prerelease: false },
  ];
  assertEquals(updateTarget("1.0.12", newer, "current"), "1.0.14");
  // A console pulled as `latest` onto the file of an older release.
  assertEquals(updateTarget("1.0.13", [], "release"), "1.0.13");
  assertEquals(updateTarget("1.0.13", [], "current"), null);
  // Edited by hand, with nothing newer: nothing to offer.
  assertEquals(updateTarget("1.0.13", [], "edited"), null);
  assertEquals(updateTarget("1.0.13", null, "current"), null);
});
