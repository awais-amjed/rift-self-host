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

const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 100;

/**
 * Page through one DM conversation (both directions between the caller and
 * [peer_id]). Same cursor modes as list_messages: `before_id` for history
 * (newest-first), `after_id` for live catch-up (oldest-first). Rows carry the
 * sender's display name and Ed25519 public key for signature verification.
 * Only a participant can read a conversation — the pair filter is always
 * anchored on the authenticated caller.
 */
Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const { peer_id, before_id, after_id, limit } = await req.json();
    const token = extractBearerToken(req);

    const auth = await authenticateToken(supabase, token);
    if (isAuthError(auth)) return auth;

    if (!peer_id) {
      return CustomResponse.error("Missing required field: peer_id", EC.MISSING_FIELDS);
    }
    if (before_id !== undefined && after_id !== undefined) {
      return CustomResponse.error(
        "Provide at most one of before_id, after_id",
        EC.MISSING_FIELDS,
      );
    }

    const pageSize = Number.isInteger(limit) && limit > 0
      ? Math.min(limit, MAX_LIMIT)
      : DEFAULT_LIMIT;

    const m = DBSchema.dmMessages;
    let query = supabase
      .from(m.tableName)
      .select(
        `${m.id}, ${m.createdAt}, ${m.senderId}, ${m.recipientId},` +
        ` ${m.ciphertext}, ${m.nonce}, ${m.signature}, ${m.keyVersion},` +
        ` ${m.editedAt},` +
        // Two FKs point at users — disambiguate the embed by column.
        ` sender:${DBSchema.users.tableName}!${m.senderId}(${DBSchema.users.displayName}, ${DBSchema.users.publicKey})`,
      )
      .or(
        `and(${m.senderId}.eq.${auth.userId},${m.recipientId}.eq.${peer_id}),` +
        `and(${m.senderId}.eq.${peer_id},${m.recipientId}.eq.${auth.userId})`,
      )
      .limit(pageSize);

    if (after_id !== undefined) {
      query = query.gt(m.id, after_id).order(m.id, { ascending: true });
    } else if (before_id !== undefined) {
      query = query.lt(m.id, before_id).order(m.id, { ascending: false });
    } else {
      query = query.order(m.id, { ascending: false });
    }

    const { data, error } = await query;
    if (error) {
      return CustomResponse.error("Error listing messages", EC.DB_ERROR, error);
    }

    const messages = ((data ?? []) as Record<string, any>[]).map((row) => {
      const sender = row["sender"] as Record<string, any> | null;
      return {
        id: row[m.id],
        created_at: row[m.createdAt],
        sender_id: row[m.senderId],
        recipient_id: row[m.recipientId],
        sender_name: sender?.[DBSchema.users.displayName] ?? "Unknown",
        sender_public_key: sender?.[DBSchema.users.publicKey] ?? null,
        ciphertext: row[m.ciphertext],
        nonce: row[m.nonce],
        signature: row[m.signature],
        key_version: row[m.keyVersion],
      };
    });

    return CustomResponse.success({ messages, has_more: messages.length === pageSize });
  } catch (err) {
    return CustomResponse.error(`Unexpected error: ${err}`, EC.UNEXPECTED_ERROR, err);
  }
});
