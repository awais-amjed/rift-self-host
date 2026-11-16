/**
 * A call region runs the main server's LiveKit, from one compose file of its
 * own (`region-compose.yml`) with no console beside it. Its settings used to be
 * copied by hand from the docs, and nothing noticed when the main stack's moved
 * on. These fail when the two differ.
 */
import { assertEquals, assertStringIncludes } from "jsr:@std/assert@1";
import { parse } from "jsr:@std/yaml@1";
import { LIVEKIT_AUDIO_FLAGS } from "./config_files.ts";

const read = (path: string) => Deno.readTextFile(new URL(path, import.meta.url));
const region = () => read("../../../region-compose.yml");
const main = () => read("../../../docker-compose.yml");

/** The text of one top-level service, up to the next one. */
function service(compose: string, name: string): string {
  const after = compose.split(`\n  ${name}:\n`)[1];
  if (after === undefined) throw new Error(`no ${name} service`);
  return after.split(/\n {2}[a-z][a-z0-9-]*:\n/)[0];
}

function field(text: string, key: string): string | undefined {
  return text.match(new RegExp(`^ {4}${key}: (.+)$`, "m"))?.[1].trim();
}

function commandWords(text: string): string[] {
  const command = text.match(/^ {4}command: \[([^\]]*)\]/m)?.[1] ?? "";
  return [...command.matchAll(/"([^"]*)"/g)].map((m) => m[1]);
}

Deno.test("a region runs the main server's LiveKit image", async () => {
  const image = field(service(await region(), "livekit"), "image");
  assertEquals(image, field(service(await main(), "livekit"), "image"));
});

Deno.test("a region tunes its speakers like the main server", async () => {
  // The main stack's command also names its config file; a region's config
  // comes from LIVEKIT_CONFIG instead, so its command is the flags alone.
  assertEquals(commandWords(service(await region(), "livekit")), LIVEKIT_AUDIO_FLAGS);
});

Deno.test("a region's room settings are the main server's", async () => {
  const livekit = service(await region(), "livekit");
  const template = await read("../../templates/livekit/livekit.yaml");
  for (
    const line of ["auto_create: true", "empty_timeout: 300", "use_external_ip: true"]
  ) {
    assertStringIncludes(livekit, line);
    assertStringIncludes(template, line);
  }
  assertStringIncludes(livekit, "port: 7880");
  assertStringIncludes(livekit, "udp_port: 7882");
  assertStringIncludes(livekit, "tcp_port: 7881");
});

/** [yaml] parsed with every placeholder made one value, less what is a region's own. */
function settings(yaml: string, placeholder: RegExp): Record<string, unknown> {
  // deno-lint-ignore no-explicit-any
  const config = parse(yaml.replace(placeholder, "X")) as any;
  delete config.keys;
  delete config.webhook.urls;
  delete config.rtc.udp_port;
  delete config.rtc.tcp_port;
  return config;
}

Deno.test("every LiveKit setting of a region is the main server's", async () => {
  // A list of lines to look for missed a setting added to the template, and
  // found one in a comment. This compares the whole parsed config: only the
  // key pair, where the webhook goes and the port numbers may differ.
  const livekit = service(await region(), "livekit");
  const block = livekit.split("LIVEKIT_CONFIG: |\n")[1].split(/\n(?! {8}| *$)/)[0];
  const inline = block.split("\n").map((line) => line.slice(8)).join("\n");
  const template = await read("../../templates/livekit/livekit.yaml");
  assertEquals(settings(inline, /\$\{[^}]*\}/g), settings(template, /\{\{[A-Z_]+\}\}/g));
});

Deno.test("a region publishes the ports LiveKit advertises", async () => {
  // LiveKit tells callers the port it listens on, so each is published under
  // the same number.
  const livekit = service(await region(), "livekit");
  assertStringIncludes(livekit, '"7882:7882/udp"');
  assertStringIncludes(livekit, '"7881:7881"');
});

Deno.test("a region's Caddy is the main server's, and can be left off", async () => {
  const caddy = service(await region(), "caddy");
  assertEquals(field(caddy, "image"), field(service(await main(), "caddy"), "image"));
  assertEquals(field(caddy, "profiles"), "[caddy]");
});

Deno.test("a region refuses to start without its values", async () => {
  const compose = await region();
  for (
    const name of [
      "REGION_DOMAIN",
      "LIVEKIT_API_KEY",
      "LIVEKIT_API_SECRET",
      "MAIN_SERVER",
    ]
  ) {
    assertStringIncludes(compose, `\${${name}:?`);
  }
});

Deno.test("IPv6 stays off for a region's LiveKit", async () => {
  assertStringIncludes(
    service(await region(), "livekit"),
    "net.ipv6.conf.all.disable_ipv6: 1",
  );
});
