import { assertEquals, assertStringIncludes } from "jsr:@std/assert@1";
import { newerDatabase } from "./upgrade.ts";

const plan = (unknown: string[] = []) => ({
  applied: [],
  pending: [],
  drifted: [],
  unknown,
});

Deno.test("an older console put back by hand does not apply itself", () => {
  assertEquals(newerDatabase(plan(), "1.9.0", "1.9.0"), null);
  assertEquals(newerDatabase(plan(), "1.8.0", "1.9.0"), null);
  assertEquals(newerDatabase(plan(), null, "1.9.0"), null);
  assertStringIncludes(newerDatabase(plan(), "1.9.1", "1.9.0")!, "newer than");
  assertStringIncludes(
    newerDatabase(plan(["045_restored_grants.sql"]), "1.9.0", "1.9.0")!,
    "045_restored_grants.sql",
  );
});
