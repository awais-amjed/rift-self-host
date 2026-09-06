import {
  assert,
  assertEquals,
  assertStringIncludes,
  assertThrows,
} from "jsr:@std/assert@1";
import { placeholders, render, renderEnv, renderLocalOverride } from "./config_files.ts";
import { defaults } from "./options.ts";
import { generateSecrets } from "./secrets.ts";

const context = async () => ({
  ...defaults,
  domain: "chat.example.com",
  secrets: await generateSecrets(),
});

Deno.test("a placeholder is replaced, everywhere it appears", () => {
  assertEquals(
    render("{{DOMAIN}} and {{DOMAIN}}", { DOMAIN: "a.example" }),
    "a.example and a.example",
  );
});

Deno.test("Kong's and Docker's own syntax survives rendering", () => {
  // kong.yml is full of $(...) router expressions and the compose file of
  // ${VAR}. A template engine would try to interpret both; this one must not
  // touch anything that is not {{NAME}}.
  const source =
    "$(query_params.apikey) ${POSTGRES_PASSWORD} {{DOMAIN}} $((a and b) or c)";
  assertEquals(
    render(source, { DOMAIN: "x" }),
    "$(query_params.apikey) ${POSTGRES_PASSWORD} x $((a and b) or c)",
  );
});

Deno.test("a placeholder nobody supplied is an error, not an empty string", () => {
  // Silently rendering `keys:\n  :` would give LiveKit a config it accepts and
  // a server that refuses every token.
  assertThrows(
    () => render("{{LIVEKIT_API_KEY}}", {}),
    Error,
    "LIVEKIT_API_KEY",
  );
});

Deno.test("every shipped template renders to something with the real values in it", async () => {
  const ctx = await context();
  const values = placeholders(ctx);
  const root = new URL("../../templates/", import.meta.url).pathname;

  // Each file paired with a value that must survive into the output. Asserting
  // on the *result* rather than on the absence of "{{" is deliberate: a
  // placeholder can be broken without being removed. `deno fmt` treats these
  // as YAML and rewrites {{NAME}} into { { NAME } }, which no longer matches
  // the pattern, renders to itself, and hands LiveKit a config it accepts and
  // reads as a key literally named "{ { LIVEKIT_API_KEY } }".
  const expectations: [string, string][] = [
    ["api/kong.yml", ctx.secrets.anonKey],
    ["api/kong.yml", ctx.secrets.serviceRoleKey],
    // The opaque pair and what Kong swaps each for. A placeholder missed here
    // renders as itself, and Kong then holds a credential literally named
    // "{{PUBLISHABLE_KEY}}" — which fails closed, but only once a client tries.
    ["api/kong.yml", ctx.secrets.publishableKey],
    ["api/kong.yml", ctx.secrets.secretKey],
    ["api/kong.yml", ctx.secrets.anonKeyAsymmetric],
    ["api/kong.yml", ctx.secrets.serviceRoleKeyAsymmetric],
    ["caddy/Caddyfile", ctx.domain],
    ["livekit/livekit.yaml", ctx.secrets.livekitApiKey],
    ["livekit/livekit.yaml", ctx.secrets.livekitApiSecret],
  ];

  for (const [file, expected] of expectations) {
    const source = await Deno.readTextFile(root + file);
    // Rendering is half the assertion: an unsupplied placeholder throws.
    const rendered = render(source, values);
    assertStringIncludes(rendered, expected);
    // Caddyfile blocks use braces of their own, so only doubled ones —
    // adjacent or split by whitespace — mean an unrendered placeholder.
    assert(
      !/\{\s*\{/.test(rendered),
      `${file} still holds an unrendered placeholder`,
    );
  }
});

Deno.test("the environment file carries a usable URL and both keys", async () => {
  const env = renderEnv(await context());
  assertStringIncludes(env, "API_EXTERNAL_URL=https://chat.example.com");
  assertStringIncludes(env, "RIFT_DOMAIN=chat.example.com");
  // https, always: Android blocks cleartext, so an http:// server is a server
  // no phone can reach.
  assert(!env.includes("API_EXTERNAL_URL=http://"));

  for (const key of ["POSTGRES_PASSWORD", "JWT_SECRET", "ANON_KEY", "SERVICE_ROLE_KEY"]) {
    assertStringIncludes(env, `${key}=`);
  }
});

Deno.test("the console stays on the loopback unless moved deliberately", async () => {
  assertStringIncludes(renderEnv(await context()), "CONSOLE_BIND=127.0.0.1");
});

/** The two values that are JSON documents rather than plain tokens. */
const JSON_SETTINGS = new Set(["JWT_KEYS", "JWT_JWKS"]);

Deno.test("no generated value needs quoting in an env file", async () => {
  // docker compose reads .env itself, and its parser has opinions about
  // spaces, quotes and '#'. Generated values are alphanumeric and JWTs are
  // base64url, so no line here needs escaping.
  const env = renderEnv(await context());
  for (const line of env.split("\n")) {
    if (line.startsWith("#") || line.trim() === "") continue;
    const name = line.slice(0, line.indexOf("="));
    if (JSON_SETTINGS.has(name)) continue;
    const value = line.slice(line.indexOf("=") + 1);
    assert(
      /^[A-Za-z0-9._:/@-]*$/.test(value),
      `${name} needs quoting: ${value}`,
    );
  }
});

Deno.test("the JWK settings are single-line JSON with nothing compose eats", async () => {
  const env = renderEnv(await context());
  const lines = new Map(
    env.split("\n").filter((l) => l.includes("=")).map((l) => [
      l.slice(0, l.indexOf("=")),
      l.slice(l.indexOf("=") + 1),
    ]),
  );

  for (const name of JSON_SETTINGS) {
    const value = lines.get(name);
    assert(value !== undefined, `${name} is missing`);
    // Parses, so no newline snuck in and split the value across two lines.
    JSON.parse(value!);
    // '#' would start a comment mid-value; '$' would be substituted. Neither
    // can occur in base64url or in these field names, and asserting it means a
    // future field that does breaks a test rather than a stack.
    assert(!value!.includes("#"), `${name} contains a comment character`);
    assert(!value!.includes("$"), `${name} contains a substitution`);
  }
});

Deno.test("the published JWKS carries no private key material", async () => {
  // `d` is the EC private scalar. Publishing it at /.well-known/jwks.json
  // would let any reader mint sessions for this server.
  const { secrets } = await context();
  for (const key of secrets.signingKeys.verifying.keys) {
    assertEquals(key.d, undefined, "public JWKS must not carry 'd'");
  }
  const signing = secrets.signingKeys.signing.find((k) => k.kty === "EC");
  assert(signing?.d !== undefined, "the signing key must carry 'd'");
});

Deno.test("only the EC key is allowed to sign", async () => {
  // GoTrue picks a signing key from JWT_KEYS. If the legacy symmetric key were
  // eligible it could pick that, sign HS256, and put the stack straight back
  // into the failure the EC key exists to prevent.
  const { secrets } = await context();
  const symmetric = secrets.signingKeys.signing.find((k) => k.kty === "oct");
  assertEquals(symmetric?.key_ops, undefined, "the oct key must not be signable");
});

Deno.test("the Caddyfile asks Caddy for nothing it does not need", async () => {
  // No ACME email anywhere. It could only ever have carried expiry warnings,
  // which Let's Encrypt stopped sending in June 2025, and an `email` directive
  // rendered with an empty value is a syntax error that crash-loops the one
  // container standing between the server and the internet.
  const root = new URL("../../templates/", import.meta.url).pathname;
  const rendered = render(
    await Deno.readTextFile(root + "caddy/Caddyfile"),
    placeholders(await context()),
  );

  // Only inside the comment that explains why, never as a directive.
  for (const line of rendered.split("\n")) {
    const code = line.trim();
    if (code.startsWith("#")) continue;
    assert(!code.startsWith("email"), `Caddyfile still sets an email: ${line}`);
  }
});

Deno.test("a local stack is addressed over http, a real one over https", async () => {
  const base = await context();

  const real = renderEnv(base);
  assertStringIncludes(real, "API_EXTERNAL_URL=https://chat.example.com");
  assertStringIncludes(real, "RIFT_LOCAL_TESTING=false");

  const local = renderEnv({
    ...base,
    localTesting: true,
    localAddress: "192.168.1.6",
    localPort: 18000,
  });
  assertStringIncludes(local, "API_EXTERNAL_URL=http://192.168.1.6:18000");
  assertStringIncludes(local, "RIFT_LOCAL_TESTING=true");
  // The mode has to survive a restart: the dashboard keeps saying so, and
  // creating a second server has to reach LiveKit the same way.
  assertStringIncludes(local, "RIFT_LOCAL_ADDRESS=192.168.1.6");
});

Deno.test("the local override publishes what Caddy would have fronted", () => {
  const yaml = renderLocalOverride({
    ...defaults,
    localTesting: true,
    localAddress: "192.168.1.6",
    localPort: 18000,
  });
  assertStringIncludes(yaml, '"0.0.0.0:18000:8000"');
  assertStringIncludes(yaml, '"0.0.0.0:7880:7880"');
  // Behind a router, STUN answers with the router's address and the call
  // connects with no sound. This is the line that prevents it.
  assertStringIncludes(yaml, 'LIVEKIT_RTC_NODE_IP: "192.168.1.6"');
  assertStringIncludes(yaml, 'LIVEKIT_RTC_USE_EXTERNAL_IP: "false"');
});
