import { assert, assertEquals, assertStringIncludes } from "jsr:@std/assert@1";
import { proxyContainersIn, proxyRoutes } from "./proxy.ts";

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

Deno.test("the media ports are named, because no proxy can carry them", async () => {
  const routes = await proxyRoutes(templateRoot, "chat.example.com", 8000);
  assertEquals(routes.mediaUdpPort, 7882);
  assertEquals(routes.mediaTcpPort, 7881);

  // A host that moved them says so, or the operator opens the wrong ports.
  const moved = await proxyRoutes(templateRoot, "chat.example.com", 8000, {
    udp: 8882,
    tcp: 8881,
  });
  assertEquals(moved.mediaUdpPort, 8882);
  assertEquals(moved.mediaTcpPort, 8881);

  // And they are not something the proxy is asked to route. The Caddyfile
  // names the media port once, in the comment explaining that it does *not*
  // pass through — never as a directive, which is exactly why the panel has
  // to say it somewhere an operator will read.
  const directives = routes.caddyfile.split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith("#"));
  assert(!directives.some((line) => line.includes(String(routes.mediaUdpPort))));
  assert(!directives.some((line) => line.includes(String(routes.mediaTcpPort))));
});

Deno.test("a proxy in a container gets a Caddyfile that can reach the stack", async () => {
  const routes = await proxyRoutes(templateRoot, "chat.example.com", 9000);
  const by = (place: string) => routes.variants.find((v) => v.place === place)!;

  // An installed proxy is what `caddyfile` holds.
  assertEquals(routes.variants.map((v) => v.place), ["host", "container"]);
  assertEquals(routes.caddyfile, by("host").caddyfile);

  // A container's 127.0.0.1 is its own: on a Mac mini whose Caddy ran in
  // Docker, the loopback snippet gave 502 on every path. It joins the stack's
  // network and names the containers, on their own ports, on any Docker.
  const container = by("container");
  assertStringIncludes(container.caddyfile, "reverse_proxy rift-kong:8000");
  assertStringIncludes(container.caddyfile, "reverse_proxy rift-livekit:7880");
  assert(!container.caddyfile.includes("127.0.0.1"));
  assert(container.joinsNetwork);
  assert(!by("host").joinsNetwork);
  assertEquals(routes.network, "rift_default");
});

Deno.test("the containers named are the ones the compose file names", async () => {
  const compose = await Deno.readTextFile(
    new URL("../../docker-compose.yml", import.meta.url),
  );
  assertStringIncludes(compose, "container_name: rift-kong");
  assertStringIncludes(compose, "container_name: rift-livekit");
});

Deno.test("a proxy container running beside the stack is found", () => {
  const lines = [
    "caddy\tcaddy:2-alpine\tweb\tweb_default,rift_default",
    "npm\tjc21/nginx-proxy-manager:latest\t\tbridge",
    "tr\ttraefik@sha256:abc\t\tbridge",
    // This stack's own containers are not somebody's proxy.
    "rift-kong\tkong:3.9\trift\trift_default",
    "rift-caddy\tcaddy:2\trift\trift_default",
    // A registry port is not a proxy's name.
    "app\tregistry.local:5000/myapp:1\t\tbridge",
    "db\tpostgres:17\tother\tother_default",
  ];
  assertEquals(proxyContainersIn(lines, "rift"), [
    { name: "caddy", image: "caddy:2-alpine", onStackNetwork: true },
    { name: "npm", image: "jc21/nginx-proxy-manager:latest", onStackNetwork: false },
    { name: "tr", image: "traefik@sha256:abc", onStackNetwork: false },
  ]);
});
