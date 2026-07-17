import "@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "@supabase/supabase-js";
import DBSchema from "../_shared/schema.ts";
import { corsHeaders } from "../_shared/cors.ts";
import { CustomResponse } from "../_shared/response.ts";
import * as EC from "../_shared/error_codes.ts";
import { generateSecureToken } from "../_shared/token_utils.ts";
import { timingSafeEqual } from "@std/crypto/timing-safe-equal";

const supabase = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
);

Deno.serve(async (req) => {
  // Handle CORS preflight requests
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const { name, icon_url, livekit_url, livekit_api_key, livekit_secret_key, service_key } =
      await req.json();

    const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

    const encoder = new TextEncoder();
    const providedBytes = encoder.encode(service_key ?? "");
    const expectedBytes = encoder.encode(serviceRoleKey);
    const keysMatch =
      providedBytes.byteLength === expectedBytes.byteLength &&
      timingSafeEqual(providedBytes, expectedBytes);

    if (!keysMatch) {
      return CustomResponse.error("Invalid service role key", EC.SERVER_KEY_INVALID);
    }

    if (!name || !livekit_url || !livekit_api_key || !livekit_secret_key) {
      return CustomResponse.error(
        "Missing required fields: name, livekit_url, livekit_api_key, livekit_secret_key",
        EC.MISSING_FIELDS,
      );
    }

    // Insert the new server into the database
    const { data, error } = await supabase
      .from(DBSchema.servers.tableName)
      .insert({
        [DBSchema.servers.name]: name,
        [DBSchema.servers.iconUrl]: icon_url || null,
        [DBSchema.servers.livekitUrl]: livekit_url,
        [DBSchema.servers.livekitApiKey]: livekit_api_key,
        [DBSchema.servers.livekitSecretKey]: livekit_secret_key,
      })
      .select()
      .single();

    if (error) {
      return CustomResponse.error("Error creating server", EC.DB_ERROR, error);
    }

    const serverRecord = data as Record<string, any>;
    const server_id = serverRecord[DBSchema.servers.id];

    // Generate an admin invite code (single-use)
    const inviteCode = generateSecureToken();

    const { error: inviteError } = await supabase
      .from(DBSchema.invites.tableName)
      .insert({
        [DBSchema.invites.serverId]: server_id,
        [DBSchema.invites.code]: inviteCode,
        [DBSchema.invites.isServerAdmin]: true,
        [DBSchema.invites.isChannelManager]: true,
        [DBSchema.invites.canCreateTokens]: true,
        [DBSchema.invites.maxUses]: 1,
        [DBSchema.invites.uses]: 0,
      });

    if (inviteError) {
      return CustomResponse.error("Error creating admin invite", EC.DB_ERROR, inviteError);
    }

    return CustomResponse.success({
      server_id,
      name,
      supabase_url: Deno.env.get("SUPABASE_URL"),
      supabase_key: Deno.env.get("SUPABASE_ANON_KEY"),
      invite_code: inviteCode,
    });
  } catch (error) {
    return CustomResponse.error("Unexpected error", EC.UNEXPECTED_ERROR, error);
  }
});
