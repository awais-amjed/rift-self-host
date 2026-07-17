import "@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "@supabase/supabase-js";
import { RoomServiceClient } from "livekit-server-sdk";
import DBSchema from "../_shared/schema.ts";
import { corsHeaders } from "../_shared/cors.ts";
import { CustomResponse } from "../_shared/response.ts";
import * as EC from "../_shared/error_codes.ts";
import { authenticateToken, extractBearerToken, isAuthError } from "../_shared/auth.ts";

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
    const { channel_id, participant_identity, muted } = await req.json();
    const token = extractBearerToken(req);

    if (!channel_id || !participant_identity || muted === undefined) {
      return CustomResponse.error("Missing required fields: channel_id, participant_identity, muted", EC.MISSING_FIELDS);
    }

    // Authenticate
    const auth = await authenticateToken(supabase, token);
    if (isAuthError(auth)) return auth;

    // Check permission (must be channel manager or server admin)
    if (!auth.isChannelManager && !auth.isServerAdmin) {
      return CustomResponse.error("Unauthorized: Only channel managers and server admins can mute participants", EC.PERMISSION_DENIED);
    }

    // Verify the channel exists and belongs to this server
    const { data: channelData, error: channelError } = await supabase
      .from(DBSchema.channels.tableName)
      .select(`${DBSchema.channels.id}`)
      .eq(DBSchema.channels.id, channel_id)
      .eq(DBSchema.channels.serverId, auth.serverId)
      .single();

    if (channelError || !channelData) {
      return CustomResponse.error("Channel not found", EC.CHANNEL_NOT_FOUND, channelError);
    }

    // Fetch LiveKit credentials
    const { data: server, error: serverError } = await supabase
      .from(DBSchema.servers.tableName)
      .select(`${DBSchema.servers.livekitUrl}, ${DBSchema.servers.livekitApiKey}, ${DBSchema.servers.livekitSecretKey}`)
      .eq(DBSchema.servers.id, auth.serverId)
      .single();

    if (serverError || !server) {
      return CustomResponse.error("Error fetching server credentials", EC.DB_ERROR, serverError);
    }

    const serverRecord = server as Record<string, any>;
    const livekitUrl = serverRecord[DBSchema.servers.livekitUrl];
    const apiKey = serverRecord[DBSchema.servers.livekitApiKey];
    const apiSecret = serverRecord[DBSchema.servers.livekitSecretKey];

    if (!livekitUrl || !apiKey || !apiSecret) {
      return CustomResponse.error("LiveKit credentials not configured for this server", EC.SERVER_CREDENTIALS_MISSING);
    }

    // Mute/unmute the participant
    const roomService = new RoomServiceClient(livekitUrl, apiKey, apiSecret);
    await roomService.mutePublishedTrack(channel_id, participant_identity, "", muted);

    return CustomResponse.success({
      server_id: auth.serverId,
      channel_id,
      participant_identity,
      muted,
    });
  } catch (err) {
    return CustomResponse.error(`Unexpected error: ${err}`, EC.UNEXPECTED_ERROR, err);
  }
});
