import { assert, assertEquals } from "jsr:@std/assert@1";
import { join } from "jsr:@std/path@1";
import { installFunctions, missingFunctions } from "./functions.ts";

/** Build a directory of `name/index.ts` files and return its path. */
async function sourceWith(names: string[]): Promise<string> {
  const root = await Deno.makeTempDir({ prefix: "rift-functions-" });
  for (const name of names) {
    await Deno.mkdir(join(root, name), { recursive: true });
    await Deno.writeTextFile(join(root, name, "index.ts"), `// ${name}\n`);
  }
  return root;
}

async function names(directory: string): Promise<string[]> {
  const found: string[] = [];
  for await (const entry of Deno.readDir(directory)) found.push(entry.name);
  return found.sort();
}

Deno.test("functions from every source land together", async () => {
  const app = await sourceWith(["login", "register", "_shared"]);
  const runtime = await sourceWith(["main"]);
  const target = await Deno.makeTempDir();

  const report = await installFunctions([app, runtime], target);

  assertEquals(await names(target), ["_shared", "login", "main", "register"]);
  assertEquals(report.removed, []);
  await Deno.remove(target, { recursive: true });
});

Deno.test("an endpoint withdrawn in a release stops answering", async () => {
  // The bug this exists for: `cp -r` leaves the old directory behind, so a
  // function deleted from the repo keeps serving for as long as the volume
  // lives. The development stack still carries Supabase's example `hello`
  // for exactly this reason.
  const target = await Deno.makeTempDir();
  await installFunctions([await sourceWith(["login", "hello"])], target);
  assert((await names(target)).includes("hello"));

  const report = await installFunctions([await sourceWith(["login"])], target);

  assertEquals(await names(target), ["login"]);
  assertEquals(report.removed, ["hello"]);
  await Deno.remove(target, { recursive: true });
});

Deno.test("an edited function is replaced, not merged", async () => {
  const target = await Deno.makeTempDir();

  const before = await sourceWith(["login"]);
  await Deno.writeTextFile(join(before, "login", "stale.ts"), "// removed later\n");
  await installFunctions([before], target);
  assert((await names(join(target, "login"))).includes("stale.ts"));

  // A file dropped from inside a function has to go too, or a helper deleted
  // upstream stays importable and the two versions disagree.
  await installFunctions([await sourceWith(["login"])], target);
  assertEquals(await names(join(target, "login")), ["index.ts"]);

  await Deno.remove(target, { recursive: true });
});

Deno.test("installing into nothing creates it", async () => {
  const root = await Deno.makeTempDir();
  const target = join(root, "does", "not", "exist");

  const report = await installFunctions([await sourceWith(["main"])], target);

  assertEquals(report.installed, ["main"]);
  assertEquals(await names(target), ["main"]);
  await Deno.remove(root, { recursive: true });
});

Deno.test("an empty functions volume reports every endpoint missing", async () => {
  // A restored server starts with an empty volume and a database that already
  // says it is at this release, so nothing else notices the endpoints are gone.
  const app = await sourceWith(["login", "register"]);
  const runtime = await sourceWith(["main"]);
  const target = await Deno.makeTempDir();

  assertEquals(await missingFunctions([app, runtime], target), [
    "login",
    "main",
    "register",
  ]);
  await installFunctions([app, runtime], target);
  assertEquals(await missingFunctions([app, runtime], target), []);
  await Deno.remove(target, { recursive: true });
});

Deno.test("a functions volume that was never created counts as empty", async () => {
  const target = join(await Deno.makeTempDir(), "not-there");
  assertEquals(await missingFunctions([await sourceWith(["login"])], target), ["login"]);
});
