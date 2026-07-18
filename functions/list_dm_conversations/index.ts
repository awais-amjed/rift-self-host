import "@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "@supabase/supabase-js";
import DBSchema from "../_shared/schema.ts";
import { corsHeaders } from "../_shared/cors.ts";
import { CustomResponse } from "../_shared/response.ts";
import * as EC from "../_shared/error_codes.ts";
import { authenticateToken, extractBearerToken, isAuthError } from "../_shared/auth.ts";

const supabase = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
);

/** How many recent envelopes to scan when grouping into conversations. */
const SCAN_LIMIT = 1000;

/**
 * List the caller's DM conversations on this server: one entry per peer with
 * the peer's identity material (display name, X25519 chat key for the DM
 * derivation, Ed25519 key for verification) and the latest envelope (clients
 * decrypt it for the preview). Ordered by latest activity.
 */
Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const token = extractBearerToken(req);
    const auth = await authenticateToken(supabase, token);
    if (isAuthError(auth)) return auth;

    const m = DBSchema.dmMessages;
    const { data, error } = await supabase
      .from(m.tableName)
      .select(
        `${m.id}, ${m.createdAt}, ${m.senderId}, ${m.recipientId},` +
        ` ${m.ciphertext}, ${m.nonce}, ${m.signature}, ${m.keyVersion}`,
      )
      .or(`${m.senderId}.eq.${auth.userId},${m.recipientId}.eq.${auth.userId}`)
      .order(m.id, { ascending: false })
      .limit(SCAN_LIMIT);

    if (error) {
      return CustomResponse.error("Error listing conversations", EC.DB_ERROR, error);
    }

    // Newest-first scan → the first row seen per peer is the latest envelope.
    const latestByPeer = new Map<string, Record<string, any>>();
    for (const row of (data ?? []) as Record<string, any>[]) {
      const peerId = row[m.senderId] === auth.userId
        ? row[m.recipientId] as string
        : row[m.senderId] as string;
      if (!latestByPeer.has(peerId)) latestByPeer.set(peerId, row);
    }

    if (latestByPeer.size === 0) {
      return CustomResponse.success({ conversations: [] });
    }

    const { data: peersData, error: peersError } = await supabase
      .from(DBSchema.users.tableName)
      .select(
        `${DBSchema.users.id}, ${DBSchema.users.displayName},` +
        ` ${DBSchema.users.publicKey}, ${DBSchema.users.chatPublicKey}`,
      )
      .in(DBSchema.users.id, [...latestByPeer.keys()]);

    if (peersError) {
      return CustomResponse.error("Error reading peers", EC.DB_ERROR, peersError);
    }
    const peers = new Map(
      ((peersData ?? []) as Record<string, any>[]).map((p) => [
        p[DBSchema.users.id] as string,
        p,
      ]),
    );

    const conversations = [...latestByPeer.entries()]
      .map(([peerId, row]) => {
        const peer = peers.get(peerId);
        return {
          peer_id: peerId,
          peer_name: peer?.[DBSchema.users.displayName] ?? "Unknown",
          peer_public_key: peer?.[DBSchema.users.publicKey] ?? null,
          peer_chat_public_key: peer?.[DBSchema.users.chatPublicKey] ?? null,
          last_message: {
            id: row[m.id],
            created_at: row[m.createdAt],
            sender_id: row[m.senderId],
            recipient_id: row[m.recipientId],
            ciphertext: row[m.ciphertext],
            nonce: row[m.nonce],
            signature: row[m.signature],
            key_version: row[m.keyVersion],
          },
        };
      })
      .sort((a, b) => (b.last_message.id as number) - (a.last_message.id as number));

    return CustomResponse.success({ conversations });
  } catch (err) {
    return CustomResponse.error(`Unexpected error: ${err}`, EC.UNEXPECTED_ERROR, err);
  }
});
