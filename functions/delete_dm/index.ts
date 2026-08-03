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
 * Hard-delete one server DM (migration 013).
 *
 * Sender only. Deleting a DM removes it for the recipient too — there is one
 * row, and it is the same row both sides read; a "delete for me" would need a
 * per-side hidden list, which is not worth the schema for now.
 */
Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const { message_id } = await req.json();
    const token = extractBearerToken(req);

    const auth = await authenticateToken(supabase, token);
    if (isAuthError(auth)) return auth;

    if (message_id === undefined || message_id === null) {
      return CustomResponse.error("Missing required field: message_id", EC.MISSING_FIELDS);
    }

    const { data, error } = await supabase
      .from(DBSchema.dmMessages.tableName)
      .delete()
      .eq(DBSchema.dmMessages.id, message_id)
      .eq(DBSchema.dmMessages.senderId, auth.userId)
      .select(DBSchema.dmMessages.id)
      .maybeSingle();

    if (error) {
      return CustomResponse.error("Error deleting message", EC.DB_ERROR, error);
    }
    if (!data) {
      return CustomResponse.error("Message not found, or not yours to change", EC.PERMISSION_DENIED);
    }

    return CustomResponse.success({ id: (data as Record<string, any>)[DBSchema.dmMessages.id] });
  } catch (err) {
    return CustomResponse.error(`Unexpected error: ${err}`, EC.UNEXPECTED_ERROR, err);
  }
});
