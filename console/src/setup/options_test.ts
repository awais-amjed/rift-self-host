import { assert, assertEquals } from "jsr:@std/assert@1";
import {
  defaults,
  envHasPassword,
  fields,
  optionsFromEnv,
  problemsWith,
  type SetupOptions,
} from "./options.ts";

/** A directory holding [contents] as its .env, or none at all. */
async function projectWith(contents?: string): Promise<string> {
  const directory = await Deno.makeTempDir({ prefix: "rift-options-" });
  if (contents !== undefined) {
    await Deno.writeTextFile(`${directory}/.env`, contents);
  }
  return directory;
}

const valid: SetupOptions = { ...defaults, domain: "chat.example.com" };

Deno.test("with no .env, the defaults stand", async () => {
  const directory = await projectWith();
  assertEquals(optionsFromEnv(directory), defaults);
  await Deno.remove(directory, { recursive: true });
});

Deno.test("a hand-written .env is honoured", async () => {
  // The point of the file: somebody deploying from a script, or on a host
  // where 80 is taken, should not have to come through a web page to say so.
  const directory = await projectWith(
    "RIFT_DOMAIN=chat.example.com\nHTTP_PORT=8080\nLIVEKIT_UDP_PORT=40000\n",
  );

  const options = optionsFromEnv(directory);
  assertEquals(options.domain, "chat.example.com");
  assertEquals(options.httpPort, 8080);
  assertEquals(options.livekitUdpPort, 40000);
  // Untouched keys keep their defaults rather than becoming undefined.
  assertEquals(options.httpsPort, defaults.httpsPort);
  await Deno.remove(directory, { recursive: true });
});

Deno.test("a nonsense port falls back rather than reaching compose", async () => {
  const directory = await projectWith("HTTP_PORT=not-a-port\nHTTPS_PORT=99999\n");
  const options = optionsFromEnv(directory);
  assertEquals(options.httpPort, defaults.httpPort);
  assertEquals(options.httpsPort, defaults.httpsPort);
  await Deno.remove(directory, { recursive: true });
});

Deno.test("a password in .env is never echoed into the form", async () => {
  // It would be on screen for anyone walking past, and the form does not need
  // it: a blank field means "keep what is already there".
  const directory = await projectWith("CONSOLE_PASSWORD=hunter2\n");
  assertEquals(optionsFromEnv(directory).consolePassword, "");
  assert(envHasPassword(directory), "but setup must still know it is there");
  await Deno.remove(directory, { recursive: true });
});

Deno.test("every field the form renders is a real option", () => {
  // The form is generated from this list, so a key that is not on
  // SetupOptions would render an input nothing reads.
  for (const field of fields) {
    assert(field.key in defaults, `${field.key} is not a SetupOptions key`);
  }
});

Deno.test("a domain is required", () => {
  const problems = problemsWith({ ...valid, domain: "  " });
  assertEquals(problems.length, 1);
  assert(problems[0].includes("domain is required"));
});

Deno.test("a domain with a scheme is corrected, not accepted", () => {
  // `https://https://chat.example.com` is what it would otherwise become, and
  // the failure would arrive as a certificate that never issues.
  assert(
    problemsWith({ ...valid, domain: "https://chat.example.com" })[0].includes(
      "without http",
    ),
  );
  assert(
    problemsWith({ ...valid, domain: "chat.example.com/rift" })[0].includes(
      "without a path",
    ),
  );
});

Deno.test("a valid set has nothing to say about it", () => {
  assertEquals(problemsWith(valid), []);
});

Deno.test("two services on one port is refused here, not in a compose log", () => {
  const problems = problemsWith({ ...valid, httpsPort: 80 });
  assertEquals(problems.length, 1);
  assert(problems[0].includes("port 80"), problems[0]);
});

Deno.test("voice may share a number across UDP and TCP", () => {
  // Different stacks: 7882/udp and 7882/tcp do not collide.
  assertEquals(problemsWith({ ...valid, livekitTcpPort: valid.livekitUdpPort }), []);
});

Deno.test("a port outside the range is refused", () => {
  assert(problemsWith({ ...valid, httpPort: 0 }).length > 0);
  assert(problemsWith({ ...valid, httpPort: 70000 }).length > 0);
});

Deno.test("local testing wants an address instead of a domain", () => {
  // The whole point of the mode is the addresses a certificate cannot be
  // issued for, so a domain must not be required — and must not be silently
  // demanded through the back door either.
  const local: SetupOptions = {
    ...defaults,
    localTesting: true,
    localAddress: "192.168.1.6",
    domain: "",
  };
  assertEquals(problemsWith(local), []);

  const problems = problemsWith({ ...local, localAddress: "  " });
  assertEquals(problems.length, 1);
  assert(problems[0].includes("192.168.1.6"), problems[0]);
});

Deno.test("a scheme on the LAN address is corrected, not accepted", () => {
  // `http://http://192.168.1.6:18000` is what it would otherwise become.
  const problems = problemsWith({
    ...defaults,
    localTesting: true,
    localAddress: "http://192.168.1.6",
  });
  assert(problems[0].includes("without http"), problems[0]);
});

Deno.test("the local API port cannot collide with the console", () => {
  const problems = problemsWith({
    ...defaults,
    localTesting: true,
    localAddress: "192.168.1.6",
    localPort: defaults.consolePort,
  });
  assert(problems.some((p) => p.includes("port")), problems.join("; "));
});
