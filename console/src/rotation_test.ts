import {
  assert,
  assertEquals,
  assertStringIncludes,
  assertThrows,
} from "jsr:@std/assert@1";
import {
  AFFECTED,
  DATABASE_ROLES,
  isRotationKind,
  jwtSettingStatement,
  livekitStatement,
  passwordStatements,
  realtimeDatabaseTenant,
  servicesToRecreate,
  withLivekitKey,
} from "./rotation.ts";

const current = { livekitApiKey: "APIcurrent0001", livekitApiSecret: "currentsecret" };
const next = { livekitApiKey: "APInext0000001", livekitApiSecret: "nextsecret" };

Deno.test("the voice key is swapped and the rest of livekit.yaml is left alone", () => {
  // A busy server widens udp_port to a range in this file. Rendering the
  // template again would put it back to one port without saying so.
  const yaml = "port: 7880\nrtc:\n  udp_port: 7882-7889\nkeys:\n" +
    "  APIcurrent0001: currentsecret\nlogging:\n  level: info\n";
  assertEquals(
    withLivekitKey(yaml, current, next),
    yaml.replace("APIcurrent0001: currentsecret", "APInext0000001: nextsecret"),
  );
});

Deno.test("a livekit.yaml with a hand-changed key is refused without naming a secret", () => {
  const yaml = "keys:\n  APIsomethingelse: othersecret\n";
  const error = assertThrows(() => withLivekitKey(yaml, current, next)) as Error;
  for (const secret of ["othersecret", "currentsecret", "nextsecret"]) {
    assert(!error.message.includes(secret), `the message shows ${secret}`);
  }
});

Deno.test("only servers on this stack's own LiveKit get the new key", () => {
  // update_server lets an admin point a server at a LiveKit elsewhere. Those
  // rows hold somebody else's credentials.
  const statement = livekitStatement(current.livekitApiKey, next);
  assertStringIncludes(statement, "WHERE livekit_api_key = 'APIcurrent0001'");
  assertStringIncludes(statement, "SET livekit_api_key = 'APInext0000001'");
  assertStringIncludes(statement, "livekit_secret_key = 'nextsecret'");
});

Deno.test("the password changes for every role that shares it, and no other", () => {
  const sql = passwordStatements("newpassword");
  const roles = [...sql.matchAll(/^ALTER ROLE (\w+) WITH PASSWORD 'newpassword';$/gm)]
    .map((match) => match[1]);
  assertEquals(roles, [...DATABASE_ROLES]);
  assertEquals(sql.split("\n").length, DATABASE_ROLES.length);
});

Deno.test("a quote in a secret cannot end the statement", () => {
  assertStringIncludes(passwordStatements("it's"), "PASSWORD 'it''s';");
  assertStringIncludes(jwtSettingStatement("it's"), "TO 'it''s';");
});

Deno.test("only services this stack has are recreated", () => {
  // Studio and meta exist only once their profile has been started, and
  // recreating a service that never ran would start it.
  const running = [
    "console",
    "db",
    "kong",
    "auth",
    "rest",
    "realtime",
    "storage",
    "functions",
  ];
  assertEquals(servicesToRecreate("signing", running), [
    "kong",
    "auth",
    "rest",
    "realtime",
    "storage",
    "functions",
  ]);
  assertEquals(servicesToRecreate("database", [...running, "studio", "meta"]), [
    "auth",
    "rest",
    "realtime",
    "storage",
    "functions",
    "studio",
    "meta",
  ]);
  assertEquals(servicesToRecreate("livekit", running), []);
});

Deno.test("no rotation recreates the database or the console", () => {
  // The database holds the passwords being changed; the console is the
  // process changing them. Recreating either mid-rotation strands the rest.
  for (const services of Object.values(AFFECTED)) {
    assert(!services.includes("db"));
    assert(!services.includes("console"));
  }
});

Deno.test("only the three rotations are accepted", () => {
  assert(isRotationKind("signing"));
  assert(!isRotationKind("everything"));
  assert(!isRotationKind(undefined));
  assert(!isRotationKind("constructor"));
});

Deno.test("Realtime is sent its database login exactly as its seed wrote it", async () => {
  // Realtime merges an update into defaults, not into what it has stored, so
  // anything left out goes back to a default that points elsewhere. The seed
  // took these from the realtime service's environment, so they are checked
  // against the compose file rather than trusted.
  const compose = await Deno.readTextFile(
    new URL("../../docker-compose.yml", import.meta.url),
  );
  const service =
    compose.split("\n  realtime:\n")[1].split(/\n {2}[a-z][a-z0-9-]*:\n/)[0];
  const environment = (name: string) =>
    service.match(new RegExp(`^\\s+${name}: (.+)$`, "m"))?.[1].trim();

  const [extension] = realtimeDatabaseTenant("the-password").extensions;
  assertEquals(extension.type, "postgres_cdc_rls");
  assertEquals(extension.settings.db_host, environment("DB_HOST"));
  assertEquals(extension.settings.db_name, environment("DB_NAME"));
  assertEquals(extension.settings.db_port, environment("DB_PORT"));
  assertEquals(extension.settings.db_user, environment("DB_USER"));
  assertEquals(extension.settings.db_password, "the-password");
});
