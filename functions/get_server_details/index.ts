import "@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "@supabase/supabase-js";
import DBSchema from "../_shared/schema.ts";
import { corsHeaders } from "../_shared/cors.ts";
import { CustomResponse } from "../_shared/response.ts";
import * as EC from "../_shared/error_codes.ts";
import { authenticateToken, extractBearerToken, isAuthError } from "../_shared/auth.ts";
import { fetchServerContext } from "../_shared/server_context.ts";

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
    const token = extractBearerToken(req);
    const auth = await authenticateToken(supabase, token);
    if (isAuthError(auth)) return auth;

    // Fetch full server context using shared helper
    const context = await fetchServerContext(supabase, {
      serverId: auth.serverId,
      tokenValue: token!,
      userId: auth.userId,
    });

    if (context instanceof Response) return context;

    return CustomResponse.success(context);
  } catch (error) {
    return CustomResponse.error("Unexpected error", EC.UNEXPECTED_ERROR, error);
  }
});
