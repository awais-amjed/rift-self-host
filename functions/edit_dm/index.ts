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

/** Replace one server-DM envelope in place. Sender only — see edit_message. */
Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const { message_id, ciphertext, nonce, signature, key_version } = await req.json();
    const token = extractBearerToken(req);

    const auth = await authenticateToken(supabase, token);
    if (isAuthError(auth)) return auth;

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

    const { data, error } = await supabase
      .from(DBSchema.dmMessages.tableName)
      .update({
        [DBSchema.dmMessages.ciphertext]: ciphertext,
        [DBSchema.dmMessages.nonce]: nonce,
        [DBSchema.dmMessages.signature]: signature,
        [DBSchema.dmMessages.keyVersion]: key_version,
        [DBSchema.dmMessages.editedAt]: new Date().toISOString(),
      })
      .eq(DBSchema.dmMessages.id, message_id)
      .eq(DBSchema.dmMessages.senderId, auth.userId)
      .select(`${DBSchema.dmMessages.id}, ${DBSchema.dmMessages.editedAt}`)
      .maybeSingle();

    if (error) {
      return CustomResponse.error("Error editing message", EC.DB_ERROR, error);
    }
    if (!data) {
      return CustomResponse.error("Message not found, or not yours to change", EC.PERMISSION_DENIED);
    }

    const row = data as Record<string, any>;
    return CustomResponse.success({
      id: row[DBSchema.dmMessages.id],
      edited_at: row[DBSchema.dmMessages.editedAt],
    });
  } catch (err) {
    return CustomResponse.error(`Unexpected error: ${err}`, EC.UNEXPECTED_ERROR, err);
  }
});
