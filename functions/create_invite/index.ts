import "@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "@supabase/supabase-js";
import DBSchema from "../_shared/schema.ts";
import { corsHeaders } from "../_shared/cors.ts";
import { CustomResponse } from "../_shared/response.ts";
import * as EC from "../_shared/error_codes.ts";
import { generateInviteCode } from "../_shared/token_utils.ts";
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
    const { max_uses, expires_in_seconds } = await req.json();
    const token = extractBearerToken(req);

    // Authenticate the caller
    const auth = await authenticateToken(supabase, token);
    if (isAuthError(auth)) return auth;

    // Check if the caller can create invites
    if (!auth.canCreateTokens) {
      return CustomResponse.error("Permission denied: user cannot create invites", EC.PERMISSION_DENIED);
    }

    // Compute expiry timestamp (null = never expires)
    const expiresAt: string | null = (expires_in_seconds != null && expires_in_seconds > 0)
      ? new Date(Date.now() + expires_in_seconds * 1000).toISOString()
      : null;

    // max_uses: explicit null → unlimited (stored as NULL in DB)
    //           explicit number → that many uses
    //           omitted (undefined) → default to 1 (single-use)
    const resolvedMaxUses = max_uses !== undefined ? max_uses : 1;

    // Invites are plain (Discord-style): everyone joins with baseline
    // permissions and admins promote members afterwards via
    // set_user_permissions. Only the hidden bootstrap invite created by
    // create_server carries elevated permissions.
    const row = {
      [DBSchema.invites.serverId]: auth.serverId,
      [DBSchema.invites.isServerAdmin]: false,
      [DBSchema.invites.isChannelManager]: false,
      [DBSchema.invites.canCreateTokens]: false,
      [DBSchema.invites.maxUses]: resolvedMaxUses,
      [DBSchema.invites.uses]: 0,
      [DBSchema.invites.expiresAt]: expiresAt,
    };

    // Short invite codes have a tiny but non-zero collision chance against the
    // `code` UNIQUE constraint — retry with a fresh code on 23505 (unique
    // violation), bail on any other DB error.
    let inviteCode = "";
    let insertError: { code?: string } | null = null;
    for (let attempt = 0; attempt < 5; attempt++) {
      inviteCode = generateInviteCode();
      const { error } = await supabase
        .from(DBSchema.invites.tableName)
        .insert({ ...row, [DBSchema.invites.code]: inviteCode });

      if (!error) {
        insertError = null;
        break;
      }
      insertError = error;
      if (error.code !== "23505") break; // not a code collision — give up
    }

    if (insertError) {
      return CustomResponse.error("Error creating invite", EC.DB_ERROR, insertError);
    }

    return CustomResponse.success({ invite_code: inviteCode });
  } catch (err) {
    return CustomResponse.error(`Unexpected error: ${err}`, EC.UNEXPECTED_ERROR, err);
  }
});
