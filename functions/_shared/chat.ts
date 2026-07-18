import { SupabaseClient } from "@supabase/supabase-js";
import DBSchema from "./schema.ts";
import { CustomResponse } from "./response.ts";
import * as EC from "./error_codes.ts";

/**
 * Verify that [channelId] exists and belongs to [serverId].
 * Returns the channel id string, or an error Response.
 */
export async function checkChannel(
  supabase: SupabaseClient,
  channelId: string | undefined,
  serverId: string,
): Promise<string | Response> {
  if (!channelId) {
    return CustomResponse.error("Missing required field: channel_id", EC.MISSING_FIELDS);
  }
  const { data, error } = await supabase
    .from(DBSchema.channels.tableName)
    .select(DBSchema.channels.id)
    .eq(DBSchema.channels.id, channelId)
    .eq(DBSchema.channels.serverId, serverId)
    .single();
  if (error || !data) {
    return CustomResponse.error("Channel not found", EC.CHANNEL_NOT_FOUND, error);
  }
  return channelId;
}

/** Field-size sanity caps for E2E envelopes — the server can't inspect
 * content, but it can refuse absurd blobs. */
export const MAX_CIPHERTEXT_B64 = 16384; // ~12 KB decoded ≈ 4000-char message
export const MAX_NONCE_B64 = 64;
export const MAX_SIGNATURE_B64 = 128;

/** Validate the envelope fields of a send_message / keyring entry payload.
 * Returns null when valid, or an error Response. */
export function checkEnvelopeFields(fields: {
  ciphertext?: unknown;
  nonce?: unknown;
  signature?: unknown;
}): Response | null {
  const { ciphertext, nonce, signature } = fields;
  if (
    typeof ciphertext !== "string" || ciphertext.length === 0 ||
    ciphertext.length > MAX_CIPHERTEXT_B64
  ) {
    return CustomResponse.error("Invalid envelope: ciphertext", EC.ENVELOPE_INVALID);
  }
  if (typeof nonce !== "string" || nonce.length === 0 || nonce.length > MAX_NONCE_B64) {
    return CustomResponse.error("Invalid envelope: nonce", EC.ENVELOPE_INVALID);
  }
  if (signature !== undefined) {
    if (
      typeof signature !== "string" || signature.length === 0 ||
      signature.length > MAX_SIGNATURE_B64
    ) {
      return CustomResponse.error("Invalid envelope: signature", EC.ENVELOPE_INVALID);
    }
  }
  return null;
}
