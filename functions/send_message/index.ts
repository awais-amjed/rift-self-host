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
 * Store one E2E message envelope (ARCHITECTURE.md §4). The server never sees
 * plaintext — it stores the AES-GCM body + the sender's Ed25519 signature as
 * opaque strings and attests only sender_id and created_at. Clients broadcast
 * a Realtime ping after a successful send; this row is the source of truth.
 */
Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const { channel_id, ciphertext, nonce, signature, key_version } = await req.json();
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

    const { data, error } = await supabase
      .from(DBSchema.messages.tableName)
      .insert({
        [DBSchema.messages.channelId]: channel_id,
        [DBSchema.messages.senderId]: auth.userId,
        [DBSchema.messages.ciphertext]: ciphertext,
        [DBSchema.messages.nonce]: nonce,
        [DBSchema.messages.signature]: signature,
        [DBSchema.messages.keyVersion]: key_version,
      })
      .select(`${DBSchema.messages.id}, ${DBSchema.messages.createdAt}`)
      .single();

    if (error || !data) {
      return CustomResponse.error("Error storing message", EC.DB_ERROR, error);
    }

    const row = data as Record<string, any>;
    return CustomResponse.success({
      id: row[DBSchema.messages.id],
      created_at: row[DBSchema.messages.createdAt],
      channel_id,
      sender_id: auth.userId,
    });
  } catch (err) {
    return CustomResponse.error(`Unexpected error: ${err}`, EC.UNEXPECTED_ERROR, err);
  }
});
