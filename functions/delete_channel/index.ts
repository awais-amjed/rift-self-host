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

Deno.serve(async (req) => {
  // Handle CORS preflight requests
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const { channel_id } = await req.json();
    const token = extractBearerToken(req);

    const auth = await authenticateToken(supabase, token);
    if (isAuthError(auth)) return auth;

    if (!channel_id) {
      return CustomResponse.error("Missing required field: channel_id", EC.MISSING_FIELDS);
    }
    if (!auth.isChannelManager) {
      return CustomResponse.error("Unauthorized: Only channel managers can delete channels", EC.PERMISSION_DENIED);
    }

    const { data: channelData, error: channelError } = await supabase
      .from(DBSchema.channels.tableName)
      .select(`${DBSchema.channels.id}, ${DBSchema.channels.serverId}`)
      .eq(DBSchema.channels.id, channel_id)
      .single();

    if (channelError || !channelData) {
      return CustomResponse.error("Channel not found", EC.CHANNEL_NOT_FOUND, channelError);
    }

    const channelRecord = channelData as Record<string, any>;
    if (channelRecord[DBSchema.channels.serverId] !== auth.serverId) {
      return CustomResponse.error("Unauthorized: Channel does not belong to your server", EC.CHANNEL_WRONG_SERVER);
    }

    const { error: deleteError } = await supabase
      .from(DBSchema.channels.tableName)
      .delete()
      .eq(DBSchema.channels.id, channel_id);

    if (deleteError) {
      return CustomResponse.error("Error deleting channel", EC.DB_ERROR, deleteError);
    }

    return CustomResponse.success({ message: "Channel deleted successfully", channel_id });
  } catch (error) {
    return CustomResponse.error(`Unexpected error: ${error}`, EC.UNEXPECTED_ERROR, error);
  }
});
