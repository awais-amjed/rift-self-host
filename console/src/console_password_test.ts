import { assert, assertEquals, assertFalse } from "jsr:@std/assert@1";
import { readEnvFile } from "./env_file.ts";
import {
  hashPassword,
  setPassword,
  storedPasswordHash,
  verifyPassword,
} from "./console_password.ts";
import { isAuthenticated, openSession } from "./web/auth.ts";

async function projectWith(env: string): Promise<string> {
  const directory = await Deno.makeTempDir();
  await Deno.writeTextFile(`${directory}/.env`, env);
  return directory;
}

Deno.test("a hash opens for its password and nothing else", async () => {
  const stored = await hashPassword("correct horse");
  assert(await verifyPassword("correct horse", stored));
  assertFalse(await verifyPassword("correct horse ", stored));
  assertFalse(await verifyPassword("", stored));
});

Deno.test("the same password hashes differently each time", async () => {
  assert(await hashPassword("a") !== await hashPassword("a"));
});

Deno.test("a hash has no $, which compose would read as a variable", async () => {
  assertFalse((await hashPassword("pa$$word")).includes("$"));
});

Deno.test("a stored value that is not a hash opens for nothing", async () => {
  // Above all the password itself, pasted where the hash goes.
  for (const stored of ["", "hunter2", "pbkdf2-sha256:x:00:00", "md5:1:00:00"]) {
    assertFalse(await verifyPassword(stored, stored), stored);
  }
});

Deno.test("a password in the clear is swapped for its hash on reading", async () => {
  const directory = await projectWith("RIFT_SETUP=done\nCONSOLE_PASSWORD=hunter2\nA=1\n");

  const stored = await storedPasswordHash(directory);

  const env = readEnvFile(directory);
  assertEquals(env.CONSOLE_PASSWORD, undefined);
  assertEquals(env.CONSOLE_PASSWORD_HASH, stored);
  assertEquals(env.A, "1");
  assert(stored !== null && await verifyPassword("hunter2", stored));
  assertFalse((await Deno.readTextFile(`${directory}/.env`)).includes("hunter2"));
  await Deno.remove(directory, { recursive: true });
});

Deno.test("a hand-written password is hashed before setup has run", async () => {
  const directory = await projectWith("CONSOLE_PASSWORD=hunter2\n");
  await storedPasswordHash(directory);
  assertEquals(readEnvFile(directory).CONSOLE_PASSWORD, undefined);
  await Deno.remove(directory, { recursive: true });
});

Deno.test("while setup runs the password stays, so setup can show it", async () => {
  const directory = await projectWith("RIFT_SETUP=running\nCONSOLE_PASSWORD=hunter2\n");
  assertEquals(await storedPasswordHash(directory), null);
  assertEquals(readEnvFile(directory).CONSOLE_PASSWORD, "hunter2");
  await Deno.remove(directory, { recursive: true });
});

Deno.test("no password at all reads as none", async () => {
  const directory = await projectWith("RIFT_SETUP=done\n");
  assertEquals(await storedPasswordHash(directory), null);
  await Deno.remove(directory, { recursive: true });
});

Deno.test("a new password replaces both the hash and any plain line", async () => {
  const old = await hashPassword("old");
  const directory = await projectWith(
    `CONSOLE_PASSWORD_HASH=${old}\nCONSOLE_PASSWORD=older\n`,
  );

  await setPassword("new", directory);

  const env = readEnvFile(directory);
  assertEquals(env.CONSOLE_PASSWORD, undefined);
  assert(await verifyPassword("new", env.CONSOLE_PASSWORD_HASH));
  assertFalse(await verifyPassword("old", env.CONSOLE_PASSWORD_HASH));
  await Deno.remove(directory, { recursive: true });
});

Deno.test("a session ends with the password it was opened under", async () => {
  // So a reset after a leak signs out whoever used the leaked password.
  const before = await hashPassword("leaked");
  const token = openSession(before);
  const request = new Request("http://console/", {
    headers: { cookie: `rift_console=${token}` },
  });

  assert(isAuthenticated(request, before));
  assertFalse(isAuthenticated(request, await hashPassword("leaked")));
  assertFalse(isAuthenticated(request, before), "and it stays ended");
});
