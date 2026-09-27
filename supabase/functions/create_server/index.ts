import "@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "@supabase/supabase-js";
import DBSchema from "../_shared/schema.ts";
import { corsHeaders } from "../_shared/cors.ts";
import { CustomResponse } from "../_shared/response.ts";
import * as EC from "../_shared/error_codes.ts";
import { generateInviteCode } from "../_shared/token_utils.ts";
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
      })
      .select()
      .single();

    if (error) {
      return CustomResponse.error("Error creating server", EC.DB_ERROR, error);
    }

    const serverRecord = data as Record<string, any>;
    const server_id = serverRecord[DBSchema.servers.id];

    // Credentials go in their own table, which nothing but the service role can
    // read — that is what lets members select the rest of the server row.
    const { error: secretsError } = await supabase
      .from(DBSchema.serverSecrets.tableName)
      .insert({
        [DBSchema.serverSecrets.serverId]: server_id,
        [DBSchema.serverSecrets.livekitApiKey]: livekit_api_key,
        [DBSchema.serverSecrets.livekitSecretKey]: livekit_secret_key,
      });

    if (secretsError) {
      // A server without credentials can never mint a voice token, so don't
      // leave one behind.
      await supabase.from(DBSchema.servers.tableName).delete().eq(DBSchema.servers.id, server_id);
      return CustomResponse.error("Error storing server credentials", EC.DB_ERROR, secretsError);
    }

    // Seed the two channels every server turns out to want. Without them the
    // admin lands in an empty sidebar and has to build the room before anyone
    // can say anything in it. Names are lowercase to match what the create
    // dialog suggests, and they differ because (server_id, name) is unique —
    // a text and a voice channel cannot both be called "general".
    const { error: channelsError } = await supabase
      .from(DBSchema.channels.tableName)
      .insert([
        {
          [DBSchema.channels.serverId]: server_id,
          [DBSchema.channels.name]: "general",
          [DBSchema.channels.channelType]: "text",
        },
        {
          [DBSchema.channels.serverId]: server_id,
          [DBSchema.channels.name]: "voice",
          [DBSchema.channels.channelType]: "voice",
        },
      ]);

    if (channelsError) {
      // Same reasoning as the credentials above: a half-made server is worse
      // than one that plainly failed. The cascade takes the secrets with it.
      await supabase.from(DBSchema.servers.tableName).delete().eq(DBSchema.servers.id, server_id);
      return CustomResponse.error("Error creating default channels", EC.DB_ERROR, channelsError);
    }

    // Generate an admin invite code (single-use).
    //
    // It names a role now rather than three booleans. The one
    // it wants is the most senior on a server that has existed for a
    // millisecond and has exactly the roles its own trigger just seeded — so
    // "highest position" is `Admin`, without this having to know the name.
    // Not `Owner`, which sits above it: that one is never named by an
    // invite. Registration hands it to the first person in, which is whoever
    // redeems this.
    const inviteCode = generateInviteCode();

    const { data: topRole, error: roleError } = await supabase
      .from("roles")
      .select("id")
      .eq("server_id", server_id)
      .eq("is_everyone", false)
      .eq("is_owner", false)
      .order("position", { ascending: false })
      .limit(1)
      .maybeSingle();

    if (roleError || !topRole) {
      return CustomResponse.error("Error reading server roles", EC.DB_ERROR, roleError);
    }

    const { error: inviteError } = await supabase
      .from(DBSchema.invites.tableName)
      .insert({
        [DBSchema.invites.serverId]: server_id,
        [DBSchema.invites.code]: inviteCode,
        [DBSchema.invites.roleId]: (topRole as Record<string, any>).id,
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
