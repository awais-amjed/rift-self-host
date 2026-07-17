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
  // Handle CORS preflight requests
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const { username } = await req.json();

    // Validate required field
    if (!username) {
      return CustomResponse.error("Missing required field: username", EC.MISSING_FIELDS);
    }

    // Check if username exists in the users table
    const { data, error } = await supabase
      .from(DBSchema.users.tableName)
      .select(DBSchema.users.id)
      .eq(DBSchema.users.username, username)
      .maybeSingle();

    if (error) {
      return CustomResponse.error("Error checking username availability", EC.DB_ERROR, error);
    }

    // If data exists, username is taken; otherwise it's available
    const isAvailable = !data;

    return CustomResponse.success({
      username,
      available: isAvailable,
    });
  } catch (err) {
    return CustomResponse.error(`Unexpected error: ${err}`, EC.UNEXPECTED_ERROR, err);
  }
});
