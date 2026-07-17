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
    const { name, channel_type } = await req.json();
    const token = extractBearerToken(req);

    const auth = await authenticateToken(supabase, token);
    if (isAuthError(auth)) return auth;

    if (!name) {
      return CustomResponse.error("Missing required field: name", EC.MISSING_FIELDS);
    }
    if (!channel_type) {
      return CustomResponse.error("Missing required field: channel_type", EC.MISSING_FIELDS);
    }
    if (channel_type !== "voice" && channel_type !== "text") {
      return CustomResponse.error("Invalid channel_type. Must be 'voice' or 'text'", EC.CHANNEL_TYPE_INVALID);
    }
    if (!auth.isChannelManager) {
      return CustomResponse.error("Unauthorized: Only channel managers can create channels", EC.PERMISSION_DENIED);
    }

    const { data: existingChannel, error: checkError } = await supabase
      .from(DBSchema.channels.tableName)
      .select(DBSchema.channels.id)
      .eq(DBSchema.channels.serverId, auth.serverId)
      .eq(DBSchema.channels.name, name)
      .maybeSingle();

    if (checkError) {
      return CustomResponse.error("Error checking for existing channel", EC.DB_ERROR, checkError);
    }
    if (existingChannel) {
      return CustomResponse.error("A channel with this name already exists in this server", EC.CHANNEL_NAME_DUPLICATE);
    }

    const { data, error } = await supabase
      .from(DBSchema.channels.tableName)
      .insert({
        [DBSchema.channels.serverId]: auth.serverId,
        [DBSchema.channels.name]: name,
        [DBSchema.channels.channelType]: channel_type,
      })
      .select(
        `${DBSchema.channels.id}, ${DBSchema.channels.name}, ${DBSchema.channels.channelType}, ${DBSchema.channels.createdAt}`,
      )
      .single();

    if (error || !data) {
      return CustomResponse.error("Error creating channel", EC.DB_ERROR, error);
    }

    const channelRecord = data as Record<string, any>;
    return CustomResponse.success({
      id: channelRecord[DBSchema.channels.id],
      name: channelRecord[DBSchema.channels.name],
      channel_type: channelRecord[DBSchema.channels.channelType],
      created_at: channelRecord[DBSchema.channels.createdAt],
    });
  } catch (error) {
    return CustomResponse.error("Unexpected error", EC.UNEXPECTED_ERROR, error);
  }
});
