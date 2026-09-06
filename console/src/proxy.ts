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

/** Everything the dashboard shows about an operator-supplied proxy. */
export interface ProxyRoutes {
  domain: string;
  /** `127.0.0.1:8000` — everything that is not signalling. */
  apiUpstream: string;
  /** `127.0.0.1:7880` — the four paths below. */
  signallingUpstream: string;
  /** The paths that must reach LiveKit rather than the API. */
  signallingPaths: string[];
  /** The stack's own Caddyfile, repointed at the published ports. */
  caddyfile: string;
}

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
): Promise<ProxyRoutes> {
  const template = await Deno.readTextFile(
    join(templateRoot, "caddy", "Caddyfile"),
  );
  const apiUpstream = `127.0.0.1:${apiPort}`;
  const signallingUpstream = `127.0.0.1:${SIGNALLING_PORT}`;
  const caddyfile = withoutHeader(render(template, { DOMAIN: domain }))
    .replace("reverse_proxy livekit:7880", `reverse_proxy ${signallingUpstream}`)
    .replace("reverse_proxy kong:8000", `reverse_proxy ${apiUpstream}`);

  return {
    domain,
    apiUpstream,
    signallingUpstream,
    signallingPaths: pathsIn(caddyfile),
    caddyfile,
  };
}
