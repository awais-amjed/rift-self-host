import { assertEquals } from "jsr:@std/assert@1";
import { parseEnv, updateSetting, updateSettings } from "./env_file.ts";

Deno.test("comments and blank lines are not settings", () => {
  assertEquals(
    parseEnv("# a note\n\nDOMAIN=example.com\n\n# another\nPORT=8080\n"),
    { DOMAIN: "example.com", PORT: "8080" },
  );
});

Deno.test("a value containing '=' keeps all of it", () => {
  // Base64 JWTs are the reason: padding is '=' and splitting on every one of
  // them would silently truncate both API keys.
  assertEquals(
    parseEnv("ANON_KEY=eyJhbGci.eyJyb2xl.sig==\n"),
    { ANON_KEY: "eyJhbGci.eyJyb2xl.sig==" },
  );
});

Deno.test("one layer of matching quotes is stripped", () => {
  assertEquals(parseEnv(`A="quoted"\nB='single'\nC=bare\n`), {
    A: "quoted",
    B: "single",
    C: "bare",
  });
});

Deno.test("a mismatched quote is part of the value", () => {
  assertEquals(parseEnv(`A="unbalanced\n`), { A: '"unbalanced' });
});

Deno.test("a line with no '=' is skipped rather than half-read", () => {
  assertEquals(parseEnv("JUST_A_WORD\nB=2\n"), { B: "2" });
});

Deno.test("updating rewrites the line rather than appending a second", async () => {
  // Two lines for one key would leave compose free to pick the later, and the
  // one this changes decides whether Realtime resets its own rate limits.
  const directory = await Deno.makeTempDir();
  await Deno.writeTextFile(
    `${directory}/.env`,
    "# header\nREALTIME_SEED=true\nJWT_SECRET=abc\n",
  );

  await updateSetting("REALTIME_SEED", "false", directory);

  const text = await Deno.readTextFile(`${directory}/.env`);
  assertEquals(text.match(/^REALTIME_SEED=/gm)?.length, 1);
  assertEquals(parseEnv(text), { REALTIME_SEED: "false", JWT_SECRET: "abc" });

  await Deno.remove(directory, { recursive: true });
});

Deno.test("updating a key that is absent adds it", async () => {
  const directory = await Deno.makeTempDir();
  await Deno.writeTextFile(`${directory}/.env`, "JWT_SECRET=abc\n");

  await updateSetting("REALTIME_SEED", "false", directory);

  assertEquals(parseEnv(await Deno.readTextFile(`${directory}/.env`)), {
    JWT_SECRET: "abc",
    REALTIME_SEED: "false",
  });
  await Deno.remove(directory, { recursive: true });
});

Deno.test("several values change in one write, and nothing else moves", async () => {
  const directory = await Deno.makeTempDir();
  const original = "# header\nJWT_SECRET=old\n\n# keys\nANON_KEY=old-anon\n" +
    "ANON_KEY_ASYMMETRIC=old-asym\nPOSTGRES_PASSWORD=keep\n";
  await Deno.writeTextFile(`${directory}/.env`, original);

  await updateSettings({ JWT_SECRET: "new", ANON_KEY: "new-anon" }, directory);

  // A prefix is not a match: ANON_KEY must not rewrite ANON_KEY_ASYMMETRIC,
  // which would put the anon JWT where Kong expects the ES256 one.
  assertEquals(
    await Deno.readTextFile(`${directory}/.env`),
    original.replace("JWT_SECRET=old", "JWT_SECRET=new")
      .replace("ANON_KEY=old-anon", "ANON_KEY=new-anon"),
  );
  await Deno.remove(directory, { recursive: true });
});

Deno.test("a key written twice by hand is rewritten both times", async () => {
  // Compose takes the later line. Rewriting only the first would leave the
  // old value as the one that wins.
  const directory = await Deno.makeTempDir();
  await Deno.writeTextFile(`${directory}/.env`, "X=old\nY=1\nX=older\n");

  await updateSettings({ X: "new" }, directory);

  assertEquals(await Deno.readTextFile(`${directory}/.env`), "X=new\nY=1\nX=new\n");
  await Deno.remove(directory, { recursive: true });
});

Deno.test("an added value goes before the final newline", async () => {
  const directory = await Deno.makeTempDir();
  await Deno.writeTextFile(`${directory}/.env`, "A=1\n");

  await updateSettings({ B: "2", C: "3" }, directory);

  assertEquals(await Deno.readTextFile(`${directory}/.env`), "A=1\nB=2\nC=3\n");
  await Deno.remove(directory, { recursive: true });
});

Deno.test("writing leaves nothing beside .env", async () => {
  const directory = await Deno.makeTempDir();
  await Deno.writeTextFile(`${directory}/.env`, "A=1\n");

  await updateSettings({ A: "2" }, directory);

  const names = [];
  for await (const entry of Deno.readDir(directory)) names.push(entry.name);
  assertEquals(names, [".env"]);
  await Deno.remove(directory, { recursive: true });
});
