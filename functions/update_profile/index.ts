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

const MAX_DISPLAY_NAME = 32;

/**
 * Update the caller's own profile on this server (migration 014).
 *
 * Self only — there is no target parameter, so this can't be aimed at anyone
 * else even by a server admin. Renaming another member is a moderation action
 * and doesn't belong on the endpoint people call to set their own name.
 *
 * `display_name` is per-server: each server is its own identity, so this
 * changes how you appear here and nowhere else. Both fields are optional;
 * passing `avatar_path: null` explicitly clears the avatar.
 */
Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const body = await req.json();
    const token = extractBearerToken(req);

    const auth = await authenticateToken(supabase, token);
    if (isAuthError(auth)) return auth;

    const update: Record<string, unknown> = {};

    if (body.display_name !== undefined) {
      const name = typeof body.display_name === "string" ? body.display_name.trim() : "";
      if (name.length === 0 || name.length > MAX_DISPLAY_NAME) {
        return CustomResponse.error(
          `Display name must be 1–${MAX_DISPLAY_NAME} characters`,
          EC.MISSING_FIELDS,
        );
      }
      update[DBSchema.users.displayName] = name;
    }

    // Distinguish "not supplied" from an explicit null, which clears it.
    if ("avatar_path" in body) {
      const path = body.avatar_path;
      if (path !== null && typeof path !== "string") {
        return CustomResponse.error("Invalid avatar_path", EC.MISSING_FIELDS);
      }
      // Only ever inside the caller's own folder — the storage RLS says the
      // same, but a row pointing at someone else's object would still be a
      // way to make the UI render it under your name.
      if (typeof path === "string" && !path.startsWith(`${auth.userId}/`)) {
        return CustomResponse.error("Invalid avatar_path", EC.PERMISSION_DENIED);
      }
      update[DBSchema.users.avatarPath] = path;
    }

    if (Object.keys(update).length === 0) {
      return CustomResponse.error("Nothing to update", EC.MISSING_FIELDS);
    }

    const { data, error } = await supabase
      .from(DBSchema.users.tableName)
      .update(update)
      .eq(DBSchema.users.id, auth.userId)
      .select(
        `${DBSchema.users.id}, ${DBSchema.users.displayName}, ${DBSchema.users.avatarPath}`,
      )
      .maybeSingle();

    if (error || !data) {
      return CustomResponse.error("Error updating profile", EC.DB_ERROR, error);
    }

    const row = data as Record<string, any>;
    return CustomResponse.success({
      id: row[DBSchema.users.id],
      display_name: row[DBSchema.users.displayName],
      avatar_path: row[DBSchema.users.avatarPath],
    });
  } catch (err) {
    return CustomResponse.error(`Unexpected error: ${err}`, EC.UNEXPECTED_ERROR, err);
  }
});
