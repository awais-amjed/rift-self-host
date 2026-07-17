import "@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "@supabase/supabase-js";
import { AccessToken, RoomServiceClient } from "livekit-server-sdk";
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
    const { channel_id, screen_share } = await req.json();
    const token = extractBearerToken(req);
    console.log(`[get_channel_token] token="${token?.substring(0,8)}...", channel_id="${channel_id}"`);

    const auth = await authenticateToken(supabase, token);
    if (isAuthError(auth)) return auth;

    if (!channel_id) {
      return CustomResponse.error("Missing required field: channel_id", EC.MISSING_FIELDS);
    }

    const { data: channelData, error: channelError } = await supabase
      .from(DBSchema.channels.tableName)
      .select(`${DBSchema.channels.id}`)
      .eq(DBSchema.channels.id, channel_id)
      .eq(DBSchema.channels.serverId, auth.serverId)
      .single();

    if (channelError || !channelData) {
      return CustomResponse.error("Channel not found", EC.CHANNEL_NOT_FOUND, channelError);
    }

    const room = channel_id;

    // Fetch user display name
    const { data: userData, error: userError } = await supabase
      .from(DBSchema.users.tableName)
      .select(`${DBSchema.users.displayName}`)
      .eq(DBSchema.users.id, auth.userId)
      .single();

    if (userError || !userData) {
      return CustomResponse.error("User not found", EC.USER_NOT_FOUND, userError);
    }

    const userRecord = userData as Record<string, any>;
    let identity = auth.userId;

    if (screen_share === true) {
      identity = `${identity}_screenshare`;
    }

    const displayName = userRecord[DBSchema.users.displayName];

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
    const apiKey = serverRecord[DBSchema.servers.livekitApiKey];
    const apiSecret = serverRecord[DBSchema.servers.livekitSecretKey];
    const livekitUrl: string = serverRecord[DBSchema.servers.livekitUrl] ?? "";

    if (!apiKey || !apiSecret) {
      return CustomResponse.error("LiveKit credentials not configured for this server", EC.SERVER_CREDENTIALS_MISSING);
    }

    // Normalise the LiveKit URL for the admin API (wss:// → https://, ws:// → http://)
    const livekitHost = livekitUrl.replace(/^wss:\/\//, "https://").replace(/^ws:\/\//, "http://");

    // Pre-create the LiveKit room server-side (idempotent — safe to call even if
    // the room already exists). This means clients never need roomCreate: true;
    // the edge function is the only thing that can create rooms.
    const roomService = new RoomServiceClient(livekitHost, apiKey, apiSecret);
    try {
      await roomService.createRoom({ name: room });
    } catch (roomErr) {
      return CustomResponse.error("Failed to ensure LiveKit room exists", EC.UNEXPECTED_ERROR, roomErr);
    }

    // Create LiveKit access token
    const at = new AccessToken(apiKey, apiSecret, {
      identity,
      name: displayName,
      ttl: "1h",
    });

    at.addGrant({
      roomCreate: false,  // room is always pre-created above; clients must not create arbitrary rooms
      roomJoin: true,
      room,
      canPublish: true,
      canSubscribe: true,
      roomAdmin: auth.isChannelManager,
    });

    const livekitToken = await at.toJwt();

    return CustomResponse.success({ token: livekitToken });
  } catch (err) {
    return CustomResponse.error(`Unexpected error: ${err}`, EC.UNEXPECTED_ERROR, err);
  }
});
