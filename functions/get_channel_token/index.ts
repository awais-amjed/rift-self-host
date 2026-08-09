import "@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "@supabase/supabase-js";
import { AccessToken, RoomServiceClient } from "livekit-server-sdk";
import { grantSources, moderationMetadata } from "../_shared/moderation.ts";
import DBSchema from "../_shared/schema.ts";
import { corsHeaders } from "../_shared/cors.ts";
import { CustomResponse } from "../_shared/response.ts";
import * as EC from "../_shared/error_codes.ts";
import { authenticateToken, extractBearerToken, isAuthError } from "../_shared/auth.ts";
import { livekitCredentials } from "../_shared/livekit.ts";

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
    const { channel_id, screen_share, device_id } = await req.json();
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

    // Fetch user display name + moderation flags
    const { data: userData, error: userError } = await supabase
      .from(DBSchema.users.tableName)
      .select(
        `${DBSchema.users.displayName}, ${DBSchema.users.isMuted}, ${DBSchema.users.isDeafened}`,
      )
      .eq(DBSchema.users.id, auth.userId)
      .single();

    if (userError || !userData) {
      return CustomResponse.error("User not found", EC.USER_NOT_FOUND, userError);
    }

    const userRecord = userData as Record<string, any>;

    // Identity = "<userId>~<deviceId>" (+ "_screenshare" for the screen-share
    // connection). The device segment lets the same user join from multiple
    // devices without a LiveKit identity collision — without it, a second
    // device joining the same room kicks the first one out. The userId prefix
    // is always server-controlled (from auth), so a client-supplied device_id
    // can never spoof another user; we still sanitise it to keep the identity
    // parseable (userId is split off on the first "~").
    const deviceSuffix =
      (typeof device_id === "string" ? device_id : "").replace(/[^a-zA-Z0-9]/g, "").slice(0, 16) ||
      "default";
    let identity = `${auth.userId}~${deviceSuffix}`;

    if (screen_share === true) {
      identity = `${identity}_screenshare`;
    }

    const displayName = userRecord[DBSchema.users.displayName];
    const isMuted: boolean = userRecord[DBSchema.users.isMuted] === true;
    const isDeafened: boolean = userRecord[DBSchema.users.isDeafened] === true;

    // Fetch LiveKit credentials. The API secret lives in `server_secrets`,
    // which no client can read — minting this token is the only reason anything
    // reads it, and it is why this endpoint stays an edge function.
    const credentials = await livekitCredentials(supabase, auth.serverId);
    if (!credentials) {
      return CustomResponse.error("LiveKit credentials not configured for this server", EC.SERVER_CREDENTIALS_MISSING);
    }
    const { apiKey, apiSecret } = credentials;

    // Pre-create the LiveKit room server-side (idempotent — safe to call even if
    // the room already exists). This means clients never need roomCreate: true;
    // the edge function is the only thing that can create rooms.
    const roomService = new RoomServiceClient(credentials.host, apiKey, apiSecret);
    try {
      await roomService.createRoom({ name: room });
    } catch (roomErr) {
      return CustomResponse.error("Failed to ensure LiveKit room exists", EC.UNEXPECTED_ERROR, roomErr);
    }

    // Create LiveKit access token. Moderation flags are enforced here — a
    // server-muted user's token cannot publish microphone audio and a
    // deafened user's token cannot subscribe, so the state survives rejoins
    // and cannot be bypassed client-side. The flags also ride along as
    // participant metadata so every client can render the moderation state.
    const at = new AccessToken(apiKey, apiSecret, {
      identity,
      name: displayName,
      ttl: "1h",
      metadata: moderationMetadata(isMuted, isDeafened),
    });

    at.addGrant({
      roomCreate: false,  // room is always pre-created above; clients must not create arbitrary rooms
      roomJoin: true,
      room,
      canPublish: true,
      // undefined = all sources. Deafened denies the mic as well as the ears.
      canPublishSources: grantSources(isMuted, isDeafened),
      canSubscribe: !isDeafened,
      roomAdmin: auth.isChannelManager,
    });

    const livekitToken = await at.toJwt();

    // Return the identity so the desktop screen-share path (which connects via
    // the Rust SDK) uses the exact identity embedded in this token instead of
    // reconstructing it client-side.
    return CustomResponse.success({ token: livekitToken, identity });
  } catch (err) {
    return CustomResponse.error(`Unexpected error: ${err}`, EC.UNEXPECTED_ERROR, err);
  }
});
