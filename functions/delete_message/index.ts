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

/**
 * Hard-delete one channel message (migration 013).
 *
 * Hard, not a tombstone: in an E2E app "deleted" has to mean the ciphertext is
 * gone, not merely hidden behind a flag the server could stop honouring.
 * Reactions cascade with the row.
 *
 * Allowed for the sender, or a channel manager / server admin moderating.
 */
Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const { message_id, channel_id } = await req.json();
    const token = extractBearerToken(req);

    const auth = await authenticateToken(supabase, token);
    if (isAuthError(auth)) return auth;

    const channel = await checkChannel(supabase, channel_id, auth.serverId);
    if (channel instanceof Response) return channel;

    if (message_id === undefined || message_id === null) {
      return CustomResponse.error("Missing required field: message_id", EC.MISSING_FIELDS);
    }

    const isModerator = auth.isChannelManager || auth.isServerAdmin;

    let query = supabase
      .from(DBSchema.messages.tableName)
      .delete()
      .eq(DBSchema.messages.id, message_id)
      .eq(DBSchema.messages.channelId, channel_id);

    // A moderator may delete anyone's message in their own server; everyone
    // else is restricted to their own, enforced by the delete itself.
    if (!isModerator) {
      query = query.eq(DBSchema.messages.senderId, auth.userId);
    }

    const { data, error } = await query
      .select(DBSchema.messages.id)
      .maybeSingle();

    if (error) {
      return CustomResponse.error("Error deleting message", EC.DB_ERROR, error);
    }
    if (!data) {
      return CustomResponse.error("Message not found, or not yours to change", EC.PERMISSION_DENIED);
    }

    return CustomResponse.success({ id: (data as Record<string, any>)[DBSchema.messages.id] });
  } catch (err) {
    return CustomResponse.error(`Unexpected error: ${err}`, EC.UNEXPECTED_ERROR, err);
  }
});
