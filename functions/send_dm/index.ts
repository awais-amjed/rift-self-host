import "@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "@supabase/supabase-js";
import DBSchema from "../_shared/schema.ts";
import { corsHeaders } from "../_shared/cors.ts";
import { CustomResponse } from "../_shared/response.ts";
import * as EC from "../_shared/error_codes.ts";
import { authenticateToken, extractBearerToken, isAuthError } from "../_shared/auth.ts";
import { checkEnvelopeFields } from "../_shared/chat.ts";

const supabase = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
);

/**
 * Store one E2E direct-message envelope (Design 1). The server never sees
 * plaintext or a key — DM keys are derived pairwise client-side. It attests
 * sender_id and created_at, and requires the recipient to be a keyed,
 * non-banned member of this server.
 */
Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const { recipient_id, ciphertext, nonce, signature, key_version } = await req.json();
    const token = extractBearerToken(req);

    const auth = await authenticateToken(supabase, token);
    if (isAuthError(auth)) return auth;

    if (!recipient_id || recipient_id === auth.userId) {
      return CustomResponse.error("Invalid recipient_id", EC.MISSING_FIELDS);
    }

    const envelopeError = checkEnvelopeFields({ ciphertext, nonce, signature });
    if (envelopeError) return envelopeError;
    if (signature === undefined) {
      return CustomResponse.error("Invalid envelope: signature", EC.ENVELOPE_INVALID);
    }
    if (!Number.isInteger(key_version) || key_version < 1) {
      return CustomResponse.error("Invalid envelope: key_version", EC.ENVELOPE_INVALID);
    }

    // Recipient must be a keyed member of this server.
    const { data: recipientData, error: recipientError } = await supabase
      .from(DBSchema.users.tableName)
      .select(
        `${DBSchema.users.id}, ${DBSchema.users.isBanned}, ${DBSchema.users.chatPublicKey}`,
      )
      .eq(DBSchema.users.id, recipient_id)
      .eq(DBSchema.users.serverId, auth.serverId)
      .single();

    if (recipientError || !recipientData) {
      return CustomResponse.error("Recipient not found", EC.USER_NOT_FOUND, recipientError);
    }
    const recipient = recipientData as Record<string, any>;
    if (recipient[DBSchema.users.isBanned]) {
      return CustomResponse.error("Recipient not found", EC.USER_NOT_FOUND);
    }
    if (!recipient[DBSchema.users.chatPublicKey]) {
      return CustomResponse.error(
        "Recipient has not published a chat key yet",
        EC.CHAT_KEY_INVALID,
      );
    }

    const { data, error } = await supabase
      .from(DBSchema.dmMessages.tableName)
      .insert({
        [DBSchema.dmMessages.senderId]: auth.userId,
        [DBSchema.dmMessages.recipientId]: recipient_id,
        [DBSchema.dmMessages.ciphertext]: ciphertext,
        [DBSchema.dmMessages.nonce]: nonce,
        [DBSchema.dmMessages.signature]: signature,
        [DBSchema.dmMessages.keyVersion]: key_version,
      })
      .select(`${DBSchema.dmMessages.id}, ${DBSchema.dmMessages.createdAt}`)
      .single();

    if (error || !data) {
      return CustomResponse.error("Error storing message", EC.DB_ERROR, error);
    }

    const row = data as Record<string, any>;
    return CustomResponse.success({
      id: row[DBSchema.dmMessages.id],
      created_at: row[DBSchema.dmMessages.createdAt],
      recipient_id,
      sender_id: auth.userId,
    });
  } catch (err) {
    return CustomResponse.error(`Unexpected error: ${err}`, EC.UNEXPECTED_ERROR, err);
  }
});
