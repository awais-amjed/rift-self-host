import "@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "@supabase/supabase-js";
import DBSchema from "../_shared/schema.ts";
import { corsHeaders } from "../_shared/cors.ts";
import { CustomResponse } from "../_shared/response.ts";
import * as EC from "../_shared/error_codes.ts";
import { authenticateToken, extractBearerToken, isAuthError } from "../_shared/auth.ts";
import { checkChannel } from "../_shared/chat.ts";

const supabase = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
);

const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 100;

/**
 * Page through a channel's message envelopes. Two cursor modes on the
 * monotonic bigserial id:
 * - `before_id`: history scroll-up — rows with id < before_id, newest first.
 * - `after_id`: live catch-up after a Realtime ping / reconnect — rows with
 *   id > after_id, oldest first.
 * Neither: the newest page.
 *
 * Each row carries the sender's display name and Ed25519 public key
 * (server-attested), so clients can verify signatures without extra
 * round-trips. Content stays opaque — decryption is entirely client-side.
 */
Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const { channel_id, before_id, after_id, limit } = await req.json();
    const token = extractBearerToken(req);

    const auth = await authenticateToken(supabase, token);
    if (isAuthError(auth)) return auth;

    const channel = await checkChannel(supabase, channel_id, auth.serverId);
    if (channel instanceof Response) return channel;

    if (before_id !== undefined && after_id !== undefined) {
      return CustomResponse.error(
        "Provide at most one of before_id, after_id",
        EC.MISSING_FIELDS,
      );
    }

    const pageSize = Number.isInteger(limit) && limit > 0
      ? Math.min(limit, MAX_LIMIT)
      : DEFAULT_LIMIT;

    let query = supabase
      .from(DBSchema.messages.tableName)
      .select(
        `${DBSchema.messages.id},` +
        ` ${DBSchema.messages.createdAt},` +
        ` ${DBSchema.messages.senderId},` +
        ` ${DBSchema.messages.ciphertext},` +
        ` ${DBSchema.messages.nonce},` +
        ` ${DBSchema.messages.signature},` +
        ` ${DBSchema.messages.keyVersion},` +
        ` ${DBSchema.users.tableName}(${DBSchema.users.displayName}, ${DBSchema.users.publicKey})`,
      )
      .eq(DBSchema.messages.channelId, channel_id)
      .limit(pageSize);

    if (after_id !== undefined) {
      query = query
        .gt(DBSchema.messages.id, after_id)
        .order(DBSchema.messages.id, { ascending: true });
    } else if (before_id !== undefined) {
      query = query
        .lt(DBSchema.messages.id, before_id)
        .order(DBSchema.messages.id, { ascending: false });
    } else {
      query = query.order(DBSchema.messages.id, { ascending: false });
    }

    const { data, error } = await query;
    if (error) {
      return CustomResponse.error("Error listing messages", EC.DB_ERROR, error);
    }

    const messages = ((data ?? []) as Record<string, any>[]).map((row) => {
      const sender = row[DBSchema.users.tableName] as Record<string, any> | null;
      return {
        id: row[DBSchema.messages.id],
        created_at: row[DBSchema.messages.createdAt],
        channel_id,
        sender_id: row[DBSchema.messages.senderId],
        sender_name: sender?.[DBSchema.users.displayName] ?? "Unknown",
        sender_public_key: sender?.[DBSchema.users.publicKey] ?? null,
        ciphertext: row[DBSchema.messages.ciphertext],
        nonce: row[DBSchema.messages.nonce],
        signature: row[DBSchema.messages.signature],
        key_version: row[DBSchema.messages.keyVersion],
      };
    });

    return CustomResponse.success({ messages, has_more: messages.length === pageSize });
  } catch (err) {
    return CustomResponse.error(`Unexpected error: ${err}`, EC.UNEXPECTED_ERROR, err);
  }
});
