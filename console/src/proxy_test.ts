import { assert, assertEquals, assertStringIncludes } from "jsr:@std/assert@1";
import { proxyRoutes } from "./proxy.ts";

const templateRoot = new URL("../templates/", import.meta.url).pathname;

Deno.test("the snippet points at the published ports, not the container names", async () => {
  const routes = await proxyRoutes(templateRoot, "chat.example.com", 8001);

  assertEquals(routes.apiUpstream, "127.0.0.1:8001");
  assertEquals(routes.signallingUpstream, "127.0.0.1:7880");
  assertStringIncludes(routes.caddyfile, "chat.example.com {");
  assertStringIncludes(routes.caddyfile, "reverse_proxy 127.0.0.1:8001");
  assertStringIncludes(routes.caddyfile, "reverse_proxy 127.0.0.1:7880");
  // An operator's proxy cannot resolve either of these — they are names on a
  // compose network it is not on.
  assert(!routes.caddyfile.includes("reverse_proxy kong:8000"));
  assert(!routes.caddyfile.includes("reverse_proxy livekit:7880"));
});

Deno.test("the signalling paths come from the Caddyfile, not a second copy", async () => {
  const routes = await proxyRoutes(templateRoot, "chat.example.com", 8000);

  // Read out of the template so that adding a path there cannot leave the
  // dashboard telling operators an older list — which would present as calls
  // failing on a route nobody knew existed.
  assertEquals(routes.signallingPaths, ["/rtc", "/rtc/*", "/twirp/*", "/validate"]);
  for (const path of routes.signallingPaths) {
    assertStringIncludes(routes.caddyfile, path);
  }
});

Deno.test("the timeouts that keep a call open survive the rewrite", async () => {
  const routes = await proxyRoutes(templateRoot, "chat.example.com", 8000);
  // Realtime and LiveKit both hold a socket for as long as somebody is in a
  // channel, and a proxy's default read timeout cuts it.
  assertStringIncludes(routes.caddyfile, "read_timeout 0");
  assertStringIncludes(routes.caddyfile, "write_timeout 0");
});

Deno.test("the snippet opens with the site block, not with our ACME footnote", async () => {
  const routes = await proxyRoutes(templateRoot, "chat.example.com", 8000);

  // Somebody pasting this already has a Caddyfile with their own issuer
  // settings; fourteen lines about why this stack sets no ACME email push the
  // part they need below the fold.
  assertEquals(routes.caddyfile.split("\n")[0], "chat.example.com {");
  assert(!routes.caddyfile.includes("ZeroSSL"));
  // The comments that say which paths go where are the point, and stay.
  assertStringIncludes(routes.caddyfile, "LiveKit's signalling");
});
