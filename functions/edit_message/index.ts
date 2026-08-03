import "@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "@supabase/supabase-js";
import DBSchema from "../_shared/schema.ts";
import { corsHeaders } from "../_shared/cors.ts";
import { CustomResponse } from "../_shared/response.ts";
import * as EC from "../_shared/error_codes.ts";
import { authenticateToken, extractBearerToken, isAuthError } from "../_shared/auth.ts";
import { checkChannel, checkEnvelopeFields } from "../_shared/chat.ts";

const supabase = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
);

/**
 * Replace one channel message's envelope in place (migration 013).
 *
 * The server still sees only ciphertext: an edit is a freshly sealed body over
 * the same row, re-signed by the sender. key_version travels with it because a
 * rotation may have happened since the original send.
 *
 * **Sender only.** A moderator can delete a message but never rewrite it —
 * putting words in someone's mouth under their name is worse than removing it.
 */
Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const { message_id, channel_id, ciphertext, nonce, signature, key_version } = await req
      .json();
    const token = extractBearerToken(req);

    const auth = await authenticateToken(supabase, token);
    if (isAuthError(auth)) return auth;

    const channel = await checkChannel(supabase, channel_id, auth.serverId);
    if (channel instanceof Response) return channel;

    const envelopeError = checkEnvelopeFields({ ciphertext, nonce, signature });
    if (envelopeError) return envelopeError;
    if (signature === undefined) {
      return CustomResponse.error("Invalid envelope: signature", EC.ENVELOPE_INVALID);
    }
    if (!Number.isInteger(key_version) || key_version < 1) {
      return CustomResponse.error("Invalid envelope: key_version", EC.ENVELOPE_INVALID);
    }
    if (message_id === undefined || message_id === null) {
      return CustomResponse.error("Missing required field: message_id", EC.MISSING_FIELDS);
    }

    // Scope the update by sender_id and channel_id as well as the row id, so
    // authorship is enforced by the write itself — no read-then-write gap.
    const { data, error } = await supabase
      .from(DBSchema.messages.tableName)
      .update({
        [DBSchema.messages.ciphertext]: ciphertext,
        [DBSchema.messages.nonce]: nonce,
        [DBSchema.messages.signature]: signature,
        [DBSchema.messages.keyVersion]: key_version,
        [DBSchema.messages.editedAt]: new Date().toISOString(),
      })
      .eq(DBSchema.messages.id, message_id)
      .eq(DBSchema.messages.channelId, channel_id)
      .eq(DBSchema.messages.senderId, auth.userId)
      .select(`${DBSchema.messages.id}, ${DBSchema.messages.editedAt}`)
      .maybeSingle();

    if (error) {
      return CustomResponse.error("Error editing message", EC.DB_ERROR, error);
    }
    if (!data) {
      return CustomResponse.error("Message not found, or not yours to change", EC.PERMISSION_DENIED);
    }

    const row = data as Record<string, any>;
    return CustomResponse.success({
      id: row[DBSchema.messages.id],
      edited_at: row[DBSchema.messages.editedAt],
    });
  } catch (err) {
    return CustomResponse.error(`Unexpected error: ${err}`, EC.UNEXPECTED_ERROR, err);
  }
});
