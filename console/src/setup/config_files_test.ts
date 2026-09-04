import {
  assert,
  assertEquals,
  assertStringIncludes,
  assertThrows,
} from "jsr:@std/assert@1";
import { placeholders, render, renderEnv } from "./config_files.ts";
import { generateSecrets } from "./secrets.ts";

const context = async () => ({
  domain: "chat.example.com",
  acmeEmail: "admin@example.com",
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

Deno.test("every placeholder the templates use is supplied", async () => {
  const values = placeholders(await context());
  const root = new URL("../../templates/", import.meta.url).pathname;

  for (const file of ["api/kong.yml", "caddy/Caddyfile", "livekit/livekit.yaml"]) {
    const source = await Deno.readTextFile(root + file);
    // Rendering is the assertion: an unsupplied placeholder throws.
    const rendered = render(source, values);
    assert(!rendered.includes("{{"), `${file} still has a placeholder`);
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

Deno.test("no generated value needs quoting in an env file", async () => {
  // docker compose reads .env itself, and its parser has opinions about
  // spaces, quotes and '#'. Generated values are alphanumeric, and JWTs use
  // only base64url — so no line here ever needs escaping.
  const env = renderEnv(await context());
  for (const line of env.split("\n")) {
    if (line.startsWith("#") || line.trim() === "") continue;
    const value = line.slice(line.indexOf("=") + 1);
    assert(
      /^[A-Za-z0-9._:/@-]*$/.test(value),
      `${line.split("=")[0]} needs quoting: ${value}`,
    );
  }
});
