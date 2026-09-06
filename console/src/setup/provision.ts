/**
 * Creating the first server, so setup ends in an invite link.
 *
 * This is the step that decides what the operator has to handle. `create_server`
 * needs the service-role key, the LiveKit URL and the LiveKit key and secret —
 * four values, three of them secret, all of them easy to paste into the wrong
 * box. Historically the operator typed all four into the app's "create server"
 * dialog, which meant the most sensitive credential the stack has took a trip
 * through somebody's clipboard for no reason: the console already holds it.
 *
 * So the console calls the endpoint itself and keeps every secret inside the
 * machine. What comes back out is a single-use admin invite, and an invite link
 * is a thing it is safe to paste.
 */

/** What the app needs in order to join, and nothing more. */
export interface ProvisionedServer {
  serverId: string;
  name: string;
  /** `https://<domain>#<code>` — the whole of what an operator copies. */
  inviteLink: string;
}

/** How `create_server` answers. Shaped by the edge function, not by us. */
interface CreateServerResponse {
  success?: boolean;
  data?: {
    server_id?: string;
    name?: string;
    invite_code?: string;
  };
  error?: string;
  message?: string;
}

/** Everything the call needs. */
export interface ProvisionOptions {
  /** Public base URL of the server, e.g. `https://chat.example.com`. */
  publicUrl: string;
  /**
   * LiveKit's signalling port, when it is published directly rather than
   * proxied. Local testing only — a real server shares the domain, so
   * signalling rides the same `wss://` the API does.
   */
  livekitSignallingPort?: number;
  /** Reached container-to-container, so setup does not wait on DNS or a cert. */
  internalUrl: string;
  serviceRoleKey: string;
  serverName: string;
  livekitApiKey: string;
  livekitApiSecret: string;
}

/**
 * The `wss://` URL clients use for voice.
 *
 * Derived from the public URL rather than configured separately: signalling
 * shares the domain (see the Caddyfile), so anything else would be a second
 * value to keep in step with the first.
 */
export function livekitUrlFor(publicUrl: string, signallingPort?: number): string {
  const scheme = publicUrl.replace(/^https:/, "wss:").replace(/^http:/, "ws:")
    .replace(/\/$/, "");
  if (signallingPort === undefined) return scheme;

  // Local testing reaches LiveKit directly, so the port is its own rather than
  // the proxy's — there is no proxy. Host only: the API's port is not this one.
  const host = scheme.replace(/^wss?:\/\//, "").split(":")[0];
  return `${scheme.startsWith("wss:") ? "wss" : "ws"}://${host}:${signallingPort}`;
}

/** Create the server and return what the operator needs. */
export async function provisionServer(
  options: ProvisionOptions,
): Promise<ProvisionedServer> {
  const endpoint = `${options.internalUrl.replace(/\/$/, "")}/functions/v1/create_server`;

  const response = await fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      name: options.serverName,
      livekit_url: livekitUrlFor(options.publicUrl, options.livekitSignallingPort),
      livekit_api_key: options.livekitApiKey,
      livekit_secret_key: options.livekitApiSecret,
      service_key: options.serviceRoleKey,
    }),
  });

  const body = await response.text();
  let parsed: CreateServerResponse;
  try {
    parsed = JSON.parse(body);
  } catch {
    throw new Error(
      `create_server answered ${response.status} with something that is not JSON: ` +
        body.slice(0, 200),
    );
  }

  // Success is `success: true` and nothing else. The edge functions answer
  // errors with HTTP 200 by convention, so the status line says nothing —
  // trusting `response.ok` here would read a refusal as a server that exists.
  const created = parsed.data;
  if (parsed.success !== true || !created?.server_id || !created.invite_code) {
    throw new Error(
      parsed.error ?? parsed.message ?? `create_server failed (HTTP ${response.status})`,
    );
  }

  return {
    serverId: created.server_id,
    name: created.name ?? options.serverName,
    // The app's Join form takes exactly this one string; the fragment is the
    // invite code and never reaches a server log, because fragments are not
    // sent in a request.
    inviteLink: `${options.publicUrl.replace(/\/$/, "")}#${created.invite_code}`,
  };
}
