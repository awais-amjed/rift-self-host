import "@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "@supabase/supabase-js";
import { RoomServiceClient, WebhookReceiver } from "livekit-server-sdk";
import DBSchema from "../_shared/schema.ts";
import { connectionKind, normaliseHost } from "../_shared/livekit.ts";
import { sweepOrphanedWatchers } from "../_shared/watch.ts";

/**
 * LiveKit's webhook: tells this server who joined and left its calls.
 *
 *   POST /functions/v1/livekit_webhook      (sent by LiveKit, never by an app)
 *
 * **Deploy with `--no-verify-jwt`.** LiveKit holds no Rift session. It signs
 * each event instead: the `Authorization` header is a token issued by one of
 * its API keys over a hash of the body, and that key's secret is in
 * `server_secrets` or `livekit_node_secrets`, which is how a node of this
 * server is told apart from anybody else.
 *
 * Used for one thing: removing a watch connection the moment its device's
 * voice connection leaves (`_shared/watch.ts`). Without it, a watcher whose
 * app had crashed went on receiving until somebody's roster read swept it.
 * A voice connection leaving and a watcher joining both prompt a sweep of the
 * room, decided from the room as it is now, so an event repeated, replayed or
 * delivered late can remove nothing that should stay.
 *
 * Every other event is answered at once and changes nothing.
 */

const supabase = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
);

/** The events that can leave a watcher without its voice connection. */
function prompted(event: string, identity: string): boolean {
  const kind = connectionKind(identity);
  switch (event) {
    case "participant_left":
    case "participant_connection_aborted":
      return kind === "voice";
    case "participant_joined":
      // Minted while its voice connection was there, which may have left
      // before this one arrived.
      return kind === "watch";
    default:
      return false;
  }
}

/** The `iss` of a token, unverified: only which key to verify it with. */
function issuerOf(token: string): string | null {
  try {
    const payload = token.split(".")[1];
    const json = atob(payload.replace(/-/g, "+").replace(/_/g, "/"));
    const iss = JSON.parse(json).iss;
    return typeof iss === "string" && iss.length > 0 ? iss : null;
  } catch {
    return null;
  }
}

/**
 * Every LiveKit of this project's servers that signs with [apiKey], with its
 * secret. Usually one: each region has its own key, and the servers sharing
 * the bundled LiveKit share its key and its address.
 */
async function nodesSigningWith(
  apiKey: string,
): Promise<{ url: string; secret: string }[]> {
  const [{ data: servers }, { data: regions }] = await Promise.all([
    supabase
      .from(DBSchema.serverSecrets.tableName)
      .select(`${DBSchema.serverSecrets.livekitSecretKey}, servers!inner(${DBSchema.servers.livekitUrl})`)
      .eq(DBSchema.serverSecrets.livekitApiKey, apiKey),
    supabase
      .from("livekit_node_secrets")
      .select("livekit_secret_key, livekit_nodes!inner(url)")
      .eq("livekit_api_key", apiKey),
  ]);

  const found = new Map<string, { url: string; secret: string }>();
  const add = (url: unknown, secret: unknown) => {
    if (typeof url !== "string" || !url || typeof secret !== "string" || !secret) return;
    found.set(`${url}\n${secret}`, { url, secret });
  };
  const one = (embed: unknown) => (Array.isArray(embed) ? embed[0] : embed) as Record<string, any> | undefined;
  for (const row of (servers ?? []) as Record<string, any>[]) {
    add(one(row.servers)?.[DBSchema.servers.livekitUrl], row[DBSchema.serverSecrets.livekitSecretKey]);
  }
  for (const row of (regions ?? []) as Record<string, any>[]) {
    add(one(row.livekit_nodes)?.url, row.livekit_secret_key);
  }
  return [...found.values()];
}

Deno.serve(async (req) => {
  if (req.method !== "POST") return new Response(null, { status: 405 });

  const body = await req.text();
  // LiveKit sends the bare token; a `Bearer ` in front is tolerated.
  const token = (req.headers.get("Authorization") ?? "").replace(/^Bearer\s+/i, "");

  // Cheap to throw away first: most events (tracks, rooms opening and
  // closing, a voice connection joining) ask nothing of this server.
  let event: string;
  let room: string;
  let identity: string;
  try {
    const parsed = JSON.parse(body);
    event = String(parsed.event ?? "");
    room = String(parsed.room?.name ?? "");
    identity = String(parsed.participant?.identity ?? "");
  } catch {
    return new Response(null, { status: 400 });
  }
  if (!room || !prompted(event, identity)) return new Response(null, { status: 200 });

  const apiKey = issuerOf(token);
  if (!apiKey) return new Response(null, { status: 401 });

  for (const node of await nodesSigningWith(apiKey)) {
    try {
      await new WebhookReceiver(apiKey, node.secret).receive(body, token);
    } catch {
      continue;
    }
    const service = new RoomServiceClient(normaliseHost(node.url), apiKey, node.secret);
    await sweepOrphanedWatchers(service, room);
    return new Response(null, { status: 200 });
  }
  return new Response(null, { status: 401 });
});
