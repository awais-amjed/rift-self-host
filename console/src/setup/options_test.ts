import { assert, assertEquals } from "jsr:@std/assert@1";
import {
  applies,
  defaults,
  envHasPassword,
  fields,
  maxFileBytesFromEnv,
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

/**
 * The form used to show every field whatever was ticked, so an operator filled
 * in a domain, picked local testing, and only found out at submit that the two
 * do not go together. These pin the rule the page now draws itself from — and
 * pin it to [problemsWith], which is the thing that actually decides.
 */
Deno.test("a field applies exactly where the stack has one", () => {
  const field = (key: string) => fields.find((f) => f.key === key)!;
  const local: SetupOptions = {
    ...defaults,
    localTesting: true,
    localAddress: "192.168.1.6",
  };
  const caddy: SetupOptions = { ...defaults, domain: "chat.example.com" };
  const proxied: SetupOptions = { ...caddy, ownProxy: true };

  // A local-testing stack has an address instead of a name, and no Caddy.
  assert(!applies(field("domain"), local));
  assert(!applies(field("ownProxy"), local), "the two are not a combination");
  assert(!applies(field("httpPort"), local));
  assert(applies(field("localAddress"), local));
  assert(applies(field("localPort"), local));

  // A real server with this stack's own Caddy: the reverse of all of it.
  assert(applies(field("domain"), caddy));
  assert(applies(field("httpPort"), caddy));
  assert(applies(field("httpsPort"), caddy));
  assert(!applies(field("localAddress"), caddy));
  assert(!applies(field("proxyPort"), caddy), "nothing to point at yet");

  // Somebody else's proxy holds 80 and 443, and needs a port to reach.
  assert(applies(field("proxyPort"), proxied));
  assert(!applies(field("httpPort"), proxied));
  assert(!applies(field("httpsPort"), proxied));
  assert(applies(field("domain"), proxied), "it is what the proxy serves");

  // The console's own settings belong to every stack.
  for (const options of [local, caddy, proxied]) {
    assert(applies(field("serverName"), options));
    assert(applies(field("consolePassword"), options));
    assert(applies(field("consolePort"), options));
    assert(applies(field("livekitUdpPort"), options));
  }
});

Deno.test("a stack made only of the fields that apply is a valid one", () => {
  // The page posts nothing it is hiding, so whatever survives `applies` has
  // to be enough on its own.
  const local: SetupOptions = {
    ...defaults,
    localTesting: true,
    localAddress: "192.168.1.6",
  };
  const proxied: SetupOptions = {
    ...defaults,
    domain: "chat.example.com",
    ownProxy: true,
  };
  for (const options of [local, proxied]) {
    const posted: Record<string, unknown> = { ...defaults };
    for (const f of fields) {
      if (applies(f, options)) posted[f.key] = options[f.key];
    }
    posted.localTesting = options.localTesting;
    assertEquals(problemsWith(posted as unknown as SetupOptions), []);
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

Deno.test("bringing your own proxy still needs the domain it will serve", () => {
  const problems = problemsWith({ ...defaults, ownProxy: true, domain: "" });
  assert(problems.some((p) => p.includes("domain is required")));
  assertEquals(
    problemsWith({ ...defaults, ownProxy: true, domain: "chat.example.com" }),
    [],
  );
});

Deno.test("80 and 443 stop being this stack's business without Caddy", () => {
  // Whoever is terminating TLS has them. Complaining that the console shares a
  // port with an HTTP listener this stack will not start is a refusal with
  // nothing behind it.
  assertEquals(
    problemsWith({
      ...defaults,
      domain: "chat.example.com",
      ownProxy: true,
      consolePort: 443,
    }),
    [],
  );
  // With Caddy, the same pair really would fight.
  assert(
    problemsWith({ ...defaults, domain: "chat.example.com", consolePort: 443 })
      .some((p) => p.includes("443")),
  );
});

Deno.test("the proxy's port cannot be one this stack already holds", () => {
  const clash = problemsWith({
    ...defaults,
    domain: "chat.example.com",
    ownProxy: true,
    proxyPort: 7880,
  });
  // 7880 is published beside it for LiveKit's signalling, so this is a
  // container that will not start — reported here rather than by Docker a
  // minute later.
  assert(clash.some((p) => p.includes("7880")));
});

Deno.test("local testing and your own proxy are not a combination", () => {
  const problems = problemsWith({
    ...defaults,
    localTesting: true,
    localAddress: "192.168.1.6",
    ownProxy: true,
  });
  assert(problems.some((p) => p.includes("Pick one")));
});

Deno.test("the largest file is read from .env in MB, and nonsense falls back", async () => {
  const set = await projectWith("RIFT_MAX_FILE_MB=2048\n");
  assertEquals(optionsFromEnv(set).maxFileMb, 2048);
  assertEquals(maxFileBytesFromEnv(set), 2147483648);
  await Deno.remove(set, { recursive: true });

  const nonsense = await projectWith("RIFT_MAX_FILE_MB=0.5\n");
  assertEquals(optionsFromEnv(nonsense).maxFileMb, defaults.maxFileMb);
  await Deno.remove(nonsense, { recursive: true });
});

Deno.test("the largest file must be a whole number of MB", () => {
  assertEquals(problemsWith({ ...valid, maxFileMb: 4096 }), []);
  for (const maxFileMb of [0, -1, 1.5, NaN]) {
    assertEquals(problemsWith({ ...valid, maxFileMb }).length, 1, `${maxFileMb}`);
  }
});
