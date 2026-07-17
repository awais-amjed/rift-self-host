import "@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "@supabase/supabase-js";
import DBSchema from "../_shared/schema.ts";
import { corsHeaders } from "../_shared/cors.ts";
import { CustomResponse } from "../_shared/response.ts";
import * as EC from "../_shared/error_codes.ts";

const supabase = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
);

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const { public_key, server_id } = await req.json();

    if (!public_key || !server_id) {
      return CustomResponse.error("Missing required fields: public_key, server_id", EC.MISSING_FIELDS);
    }

    // Verify the user exists on this server and is not banned
    const { data: userData, error: userError } = await supabase
      .from(DBSchema.users.tableName)
      .select(`${DBSchema.users.id}, ${DBSchema.users.isBanned}`)
      .eq(DBSchema.users.serverId, server_id)
      .eq(DBSchema.users.publicKey, public_key)
      .maybeSingle();

    if (userError) {
      return CustomResponse.error("Error looking up user", EC.DB_ERROR, userError);
    }

    if (!userData) {
      return CustomResponse.error("User not found", EC.USER_NOT_FOUND);
    }

    const userRecord = userData as Record<string, any>;

    if (userRecord[DBSchema.users.isBanned]) {
      return CustomResponse.error("User is banned", EC.USER_BANNED);
    }

    // Generate a cryptographically random nonce
    const nonceBytes = new Uint8Array(32);
    crypto.getRandomValues(nonceBytes);
    const nonce = Array.from(nonceBytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");

    // Store the nonce with a 60-second TTL.
    const expiresAt = new Date(Date.now() + 60_000).toISOString();

    const { error: upsertError } = await supabase
      .from(DBSchema.authChallenges.tableName)
      .upsert(
        {
          [DBSchema.authChallenges.nonce]: nonce,
          [DBSchema.authChallenges.expiresAt]: expiresAt,
          [DBSchema.authChallenges.publicKey]: public_key,
        },
        { onConflict: DBSchema.authChallenges.publicKey },
      );

    if (upsertError) {
      return CustomResponse.error("Error creating challenge", EC.DB_ERROR, upsertError);
    }

    return CustomResponse.success({ nonce });
  } catch (err) {
    return CustomResponse.error(`Unexpected error: ${err}`, EC.UNEXPECTED_ERROR, err);
  }
});
