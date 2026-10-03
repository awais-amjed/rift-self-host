/**
 * What an operator's own reverse proxy has to be told.
 *
 * A stack that skips Caddy still needs Caddy's *routing*: two upstreams behind
 * one name, split by path, with the connection timeouts that let Realtime and
 * LiveKit hold a socket open for as long as somebody is in a channel. Left to
 * work that out from the container list, an operator gets messages working and
 * calls silently failing — which is the failure this exists to prevent.
 *
 * So the answer is derived from the Caddyfile the stack would have run rather
 * than written out again here. If the paths LiveKit answers on ever change,
 * the template changes and this follows; a second copy would not.
 */
import { join } from "jsr:@std/path@1";
import { render } from "./setup/config_files.ts";

/** Where LiveKit's signalling is published for the proxy. Its own port. */
export const SIGNALLING_PORT = 7880;

/**
 * Where the operator's proxy runs, which decides how it reaches this stack.
 *
 * The stack publishes its API and LiveKit's signalling on this machine's
 * loopback only. A proxy on the machine reaches that; one in a container does
 * not, because a container's 127.0.0.1 is its own. Docker Desktop (Mac,
 * Windows) forwards `host.docker.internal` to the machine's loopback, so that
 * name works there. Docker on Linux does not — `host.docker.internal` is the
 * bridge's address, and nothing on the loopback answers it — so a proxy there
 * joins this stack's network and names the containers. Found on a Mac mini
 * whose Caddy ran in Docker: the snippet as it was gave 502 on every path.
 */
export type ProxyPlace = "host" | "dockerDesktop" | "dockerLinux";

/** One way of reaching the stack, with its Caddyfile and anything else to do. */
export interface ProxyVariant {
  place: ProxyPlace;
  label: string;
  apiUpstream: string;
  signallingUpstream: string;
  caddyfile: string;
  /** What has to change besides the Caddyfile, if anything. */
  steps: string[];
}

/** Everything the dashboard shows about an operator-supplied proxy. */
export interface ProxyRoutes {
  domain: string;
  /** `127.0.0.1:8000` — everything that is not signalling. */
  apiUpstream: string;
  /** `127.0.0.1:7880` — the four paths below. */
  signallingUpstream: string;
  /** The paths that must reach LiveKit rather than the API. */
  signallingPaths: string[];
  /**
   * Where call audio goes, which is nowhere near the proxy.
   *
   * Media is published by the compose file on every interface and travels
   * straight to these ports — a proxy cannot carry it, and routing both
   * upstreams perfectly still leaves calls connecting with no sound if they
   * are closed. Named here because this panel is the one place an operator
   * doing their own routing will look.
   */
  mediaUdpPort: number;
  mediaTcpPort: number;
  /** The stack's own Caddyfile, repointed at the published ports. */
  caddyfile: string;
  /** The same, for each place the proxy may run. The first is [caddyfile]. */
  variants: ProxyVariant[];
}

/** The network compose makes for this stack (`name: rift` in the file). */
export const STACK_NETWORK = "rift_default";

/**
 * Drop the file's opening comment block.
 *
 * Fourteen lines about why this stack's Caddy sets no ACME email — true, and
 * none of an operator's business when they are pasting the routing into a
 * Caddyfile of their own that already has whatever issuer settings they chose.
 * The comments *inside* the block stay: those explain which paths go where,
 * which is the part that is easy to get wrong.
 */
function withoutHeader(caddyfile: string): string {
  const lines = caddyfile.split("\n");
  const start = lines.findIndex((line) => {
    const code = line.trim();
    return code.length > 0 && !code.startsWith("#");
  });
  return start <= 0 ? caddyfile : lines.slice(start).join("\n");
}

/** Pull the `@livekit path ...` line out of the rendered Caddyfile. */
function pathsIn(caddyfile: string): string[] {
  const match = caddyfile.match(/@livekit\s+path\s+(.+)/);
  return match ? match[1].trim().split(/\s+/) : [];
}

/**
 * The routes for [domain], with the API published on [apiPort].
 *
 * Loopback upstreams, because that is where the override publishes them: a
 * proxy on this machine can reach them and nothing else can. A proxy that runs
 * in a container joins this stack's network and uses `kong:8000` and
 * `livekit:7880` instead — the dashboard says so beside this.
 */
export async function proxyRoutes(
  templateRoot: string,
  domain: string,
  apiPort: number,
  media: { udp: number; tcp: number } = { udp: 7882, tcp: 7881 },
): Promise<ProxyRoutes> {
  const template = await Deno.readTextFile(
    join(templateRoot, "caddy", "Caddyfile"),
  );
  const base = withoutHeader(render(template, { DOMAIN: domain }));
  const variant = (
    place: ProxyPlace,
    label: string,
    api: string,
    signalling: string,
    steps: string[] = [],
  ): ProxyVariant => ({
    place,
    label,
    apiUpstream: api,
    signallingUpstream: signalling,
    caddyfile: base
      .replace("reverse_proxy livekit:7880", `reverse_proxy ${signalling}`)
      .replace("reverse_proxy kong:8000", `reverse_proxy ${api}`),
    steps,
  });

  const variants = [
    variant(
      "host",
      "On this machine",
      `127.0.0.1:${apiPort}`,
      `127.0.0.1:${SIGNALLING_PORT}`,
    ),
    variant(
      "dockerDesktop",
      "In Docker Desktop (Mac, Windows)",
      `host.docker.internal:${apiPort}`,
      `host.docker.internal:${SIGNALLING_PORT}`,
      [
        "Nothing else to change: Docker Desktop forwards host.docker.internal " +
        "to this machine's own ports.",
      ],
    ),
    // The containers' own ports, which do not move with RIFT_PROXY_PORT.
    variant("dockerLinux", "In Docker on Linux", "rift-kong:8000", "rift-livekit:7880", [
      `Put your proxy's container on this stack's network, ${STACK_NETWORK}. ` +
      `In its compose file: networks: { rift: { external: true, name: ${STACK_NETWORK} } }, ` +
      "and list rift under the proxy's own networks. Or, until it is next " +
      `recreated: docker network connect ${STACK_NETWORK} <your proxy container>.`,
      "host.docker.internal does not work here: on Linux it reaches the " +
      "Docker bridge, and the stack publishes these ports on the loopback only.",
    ]),
  ];
  const [host] = variants;

  return {
    domain,
    apiUpstream: host.apiUpstream,
    signallingUpstream: host.signallingUpstream,
    signallingPaths: pathsIn(host.caddyfile),
    mediaUdpPort: media.udp,
    mediaTcpPort: media.tcp,
    caddyfile: host.caddyfile,
    variants,
  };
}
