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

const MAX_EMOJI_LEN = 32;

/**
 * Toggle the caller's reaction on a message (channel or server DM).
 *
 * Reactions are NOT E2E (ARCHITECTURE.md §4) — the server stores (message,
 * user, emoji) in the clear. Adding an existing reaction removes it, so one
 * call flips state either way. Returns `{ reacted }` (true = now present).
 *
 * Body: `{ scope: "channel"|"dm", channel_id?, peer_id?, message_id, emoji }`.
 * Authorization: channel membership (checkChannel) or DM participation, and the
 * target message must belong to that channel/conversation.
 */
Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const { scope, channel_id, peer_id, message_id, emoji } = await req.json();
    const token = extractBearerToken(req);

    const auth = await authenticateToken(supabase, token);
    if (isAuthError(auth)) return auth;

    if (typeof emoji !== "string" || emoji.length === 0 || emoji.length > MAX_EMOJI_LEN) {
      return CustomResponse.error("Invalid emoji", EC.MISSING_FIELDS);
    }
    if (!Number.isInteger(message_id)) {
      return CustomResponse.error("Missing required field: message_id", EC.MISSING_FIELDS);
    }

    // Resolve the reactions table + verify the target message is one the caller
    // is allowed to react to.
    let table: string;
    if (scope === "channel") {
      const channel = await checkChannel(supabase, channel_id, auth.serverId);
      if (channel instanceof Response) return channel;

      const { data: msg } = await supabase
        .from(DBSchema.messages.tableName)
        .select(DBSchema.messages.id)
        .eq(DBSchema.messages.id, message_id)
        .eq(DBSchema.messages.channelId, channel_id)
        .maybeSingle();
      if (!msg) return CustomResponse.error("Message not found", EC.MESSAGE_NOT_FOUND);
      table = DBSchema.messageReactions.tableName;
    } else if (scope === "dm") {
      if (!peer_id) {
        return CustomResponse.error("Missing required field: peer_id", EC.MISSING_FIELDS);
      }
      const m = DBSchema.dmMessages;
      const { data: msg } = await supabase
        .from(m.tableName)
        .select(m.id)
        .eq(m.id, message_id)
        .or(
          `and(${m.senderId}.eq.${auth.userId},${m.recipientId}.eq.${peer_id}),` +
          `and(${m.senderId}.eq.${peer_id},${m.recipientId}.eq.${auth.userId})`,
        )
        .maybeSingle();
      if (!msg) return CustomResponse.error("Message not found", EC.MESSAGE_NOT_FOUND);
      table = DBSchema.dmMessageReactions.tableName;
    } else {
      return CustomResponse.error("Invalid scope", EC.MISSING_FIELDS);
    }

    const R = DBSchema.messageReactions; // same column names for both tables

    // Toggle: delete if present, else insert.
    const { data: existing } = await supabase
      .from(table)
      .select(R.messageId)
      .eq(R.messageId, message_id)
      .eq(R.userId, auth.userId)
      .eq(R.emoji, emoji)
      .maybeSingle();

    if (existing) {
      const { error } = await supabase
        .from(table)
        .delete()
        .eq(R.messageId, message_id)
        .eq(R.userId, auth.userId)
        .eq(R.emoji, emoji);
      if (error) return CustomResponse.error("Error removing reaction", EC.DB_ERROR, error);
      return CustomResponse.success({ reacted: false });
    }

    const { error } = await supabase.from(table).insert({
      [R.messageId]: message_id,
      [R.userId]: auth.userId,
      [R.emoji]: emoji,
    });
    if (error) return CustomResponse.error("Error adding reaction", EC.DB_ERROR, error);
    return CustomResponse.success({ reacted: true });
  } catch (err) {
    return CustomResponse.error(`Unexpected error: ${err}`, EC.UNEXPECTED_ERROR, err);
  }
});
