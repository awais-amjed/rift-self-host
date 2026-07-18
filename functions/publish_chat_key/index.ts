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

/**
 * Publish (or refresh) the caller's X25519 chat public key. Clients call this
 * after login once they've derived their chat identity for this host — the
 * key is deterministic per (seed, host), so re-publishing is an idempotent
 * upsert. Other members read it via get_channel_key to wrap channel keys.
 */
Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const { chat_public_key } = await req.json();
    const token = extractBearerToken(req);

    const auth = await authenticateToken(supabase, token);
    if (isAuthError(auth)) return auth;

    if (typeof chat_public_key !== "string" || chat_public_key.length === 0) {
      return CustomResponse.error(
        "Missing required field: chat_public_key",
        EC.MISSING_FIELDS,
      );
    }

    // Must be valid base64 of exactly 32 bytes (X25519 public key).
    let keyBytes: Uint8Array;
    try {
      keyBytes = Uint8Array.from(atob(chat_public_key), (c) => c.charCodeAt(0));
    } catch (_) {
      return CustomResponse.error(
        "Invalid chat_public_key: not valid base64",
        EC.CHAT_KEY_INVALID,
      );
    }
    if (keyBytes.length !== 32) {
      return CustomResponse.error(
        `Invalid chat_public_key: expected 32 bytes, got ${keyBytes.length}`,
        EC.CHAT_KEY_INVALID,
      );
    }

    const { error } = await supabase
      .from(DBSchema.users.tableName)
      .update({ [DBSchema.users.chatPublicKey]: chat_public_key })
      .eq(DBSchema.users.id, auth.userId);

    if (error) {
      return CustomResponse.error("Error publishing chat key", EC.DB_ERROR, error);
    }

    return CustomResponse.success({ chat_public_key });
  } catch (err) {
    return CustomResponse.error(`Unexpected error: ${err}`, EC.UNEXPECTED_ERROR, err);
  }
});
