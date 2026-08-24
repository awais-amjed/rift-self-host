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
 * Turn push notifications on (or off) for this server.
 *
 * This server cannot wake a phone by itself — an FCM token is scoped to the
 * Firebase project the app was built against, which is Rift's, not the
 * operator's. So it relays through central over a credential the admin
 * enrolled there, and this endpoint is where that credential is put.
 *
 * It exists as an endpoint rather than a table write because `push_config` has
 * no policy and no grant at all: the secret in it is what proves a forward
 * request came from this server, and the ring triggers are the only things
 * that ever need to read it. Not even the admin who set it can read it back —
 * they held it once, on the way through, and re-enrolling is how it is
 * replaced.
 */
Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const { endpoint, relay_id: relayId, secret, disable, status } = await req.json();

    const auth = await authenticateToken(supabase, extractBearerToken(req));
    if (isAuthError(auth)) return auth;
    if (!auth.isServerAdmin) {
      return CustomResponse.error(
        "Unauthorized: Only server admins can configure push notifications",
        EC.PERMISSION_DENIED,
      );
    }

    // Whether push is on is the one thing about `push_config` a client may
    // learn, and only an admin asks: the row's existence, never its contents.
    if (status === true) {
      const { data, error } = await supabase
        .from(DBSchema.pushConfig.tableName)
        .select(DBSchema.pushConfig.relayId)
        .eq(DBSchema.pushConfig.serverId, auth.serverId)
        .maybeSingle();
      if (error) {
        return CustomResponse.error("Error reading push status", EC.DB_ERROR, error);
      }
      // The relay id, but never the secret. An admin needs the id to revoke
      // the credential on central; the secret they only ever had in transit.
      return CustomResponse.success({
        enabled: data !== null,
        relay_id: data?.[DBSchema.pushConfig.relayId] ?? null,
      });
    }

    if (disable === true) {
      const { data, error } = await supabase
        .from(DBSchema.pushConfig.tableName)
        .delete()
        .eq(DBSchema.pushConfig.serverId, auth.serverId)
        .select(DBSchema.pushConfig.relayId)
        .maybeSingle();
      if (error) {
        return CustomResponse.error("Error disabling push", EC.DB_ERROR, error);
      }
      // Handed back so the admin's client can revoke the credential on central
      // too. Dropping the row already makes it unusable — nothing else holds
      // the secret — but a revoked row is one that stops counting against the
      // handful of credentials an account may mint.
      return CustomResponse.success({
        enabled: false,
        relay_id: data?.[DBSchema.pushConfig.relayId] ?? null,
      });
    }

    // A URL rather than a host: the relay's address is central's to choose,
    // and pinning its shape here would mean a migration to move it.
    if (typeof endpoint !== "string" || !/^https:\/\/[^ ]+$/.test(endpoint) ||
      typeof relayId !== "string" || typeof secret !== "string" || secret.length < 16
    ) {
      return CustomResponse.error(
        "endpoint (https URL), relay_id and secret are all required",
        EC.MISSING_FIELDS,
      );
    }

    const { error } = await supabase
      .from(DBSchema.pushConfig.tableName)
      .upsert({
        [DBSchema.pushConfig.serverId]: auth.serverId,
        [DBSchema.pushConfig.endpoint]: endpoint,
        [DBSchema.pushConfig.relayId]: relayId,
        [DBSchema.pushConfig.secret]: secret,
        [DBSchema.pushConfig.updatedAt]: new Date().toISOString(),
      }, { onConflict: DBSchema.pushConfig.serverId });
    if (error) {
      return CustomResponse.error("Error enabling push", EC.DB_ERROR, error);
    }

    return CustomResponse.success({ enabled: true });
  } catch (error) {
    return CustomResponse.error("Unexpected error", EC.UNEXPECTED_ERROR, error);
  }
});
