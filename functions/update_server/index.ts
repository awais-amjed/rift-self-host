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
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const { name, icon_url, livekit_url, livekit_api_key, livekit_secret_key } =
      await req.json();
    const token = extractBearerToken(req);

    // Authenticate
    const auth = await authenticateToken(supabase, token);
    if (isAuthError(auth)) return auth;

    // Check if at least one field to update is provided
    if (!name && icon_url === undefined && !livekit_url && !livekit_api_key && !livekit_secret_key) {
      return CustomResponse.error(
        "At least one field to update must be provided: name, icon_url, livekit_url, livekit_api_key, or livekit_secret_key",
        EC.MISSING_FIELDS,
      );
    }

    // Check permission
    if (!auth.isServerAdmin) {
      return CustomResponse.error("Unauthorized: Only server admins can update server details", EC.PERMISSION_DENIED);
    }

    // Build update object dynamically
    const updateData: Record<string, unknown> = {};
    if (name) {
      updateData[DBSchema.servers.name] = name;
    }
    if (icon_url !== undefined) {
      updateData[DBSchema.servers.iconUrl] = icon_url;
    }
    if (livekit_url) {
      updateData[DBSchema.servers.livekitUrl] = livekit_url;
    }
    if (livekit_api_key) {
      updateData[DBSchema.servers.livekitApiKey] = livekit_api_key;
    }
    if (livekit_secret_key) {
      updateData[DBSchema.servers.livekitSecretKey] = livekit_secret_key;
    }

    // Update server details
    const { data, error } = await supabase
      .from(DBSchema.servers.tableName)
      .update(updateData)
      .eq(DBSchema.servers.id, auth.serverId)
      .select(`${DBSchema.servers.name}, ${DBSchema.servers.iconUrl}, ${DBSchema.servers.livekitUrl}`)
      .single();

    if (error) {
      return CustomResponse.error("Error updating server", EC.DB_ERROR, error);
    }
    if (!data) {
      return CustomResponse.error("Server not found", EC.SERVER_NOT_FOUND);
    }

    const serverRecord = data as Record<string, any>;

    return CustomResponse.success({
      name: serverRecord[DBSchema.servers.name],
      icon_url: serverRecord[DBSchema.servers.iconUrl],
      livekit_url: serverRecord[DBSchema.servers.livekitUrl],
    });
  } catch (error) {
    return CustomResponse.error("Unexpected error", EC.UNEXPECTED_ERROR, error);
  }
});
