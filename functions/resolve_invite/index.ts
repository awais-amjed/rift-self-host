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

/**
 * Resolve an invite code to its server id — WITHOUT consuming it.
 *
 * When several servers share one Supabase project, the client must know which
 * server it's joining *before* it can derive that server's per-`(host, serverId)`
 * SIWS identity and sign in. This unauthenticated lookup provides that: given a
 * valid, unexpired invite code it returns the target `server_id` (+ name for the
 * join UI). Registration still validates and atomically claims the invite
 * (`register_user`), so exposing the mapping here grants nothing on its own —
 * you already hold the code.
 */
Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const { invite_code } = await req.json();
    if (!invite_code) {
      return CustomResponse.error("Missing required field: invite_code", EC.MISSING_FIELDS);
    }

    const { data, error } = await supabase
      .from(DBSchema.invites.tableName)
      .select(
        `${DBSchema.invites.serverId}, ${DBSchema.invites.expiresAt},` +
          ` ${DBSchema.invites.uses}, ${DBSchema.invites.maxUses}`,
      )
      .eq(DBSchema.invites.code, invite_code)
      .maybeSingle();

    if (error) {
      return CustomResponse.error("Error resolving invite", EC.DB_ERROR, error);
    }
    if (!data) {
      return CustomResponse.error("Invalid invite code", EC.INVITE_INVALID);
    }

    const invite = data as Record<string, any>;
    const expiresAt = invite[DBSchema.invites.expiresAt];
    if (expiresAt && new Date(expiresAt as string) <= new Date()) {
      return CustomResponse.error("Invite code has expired", EC.INVITE_EXPIRED);
    }

    // Spent invites are refused here rather than by `register`, which is the
    // only other thing that counts them. Both answers are correct; this one
    // arrives before somebody has picked a username and generated a keypair
    // for a server they were never going to be let into. `max_uses` of 0 is
    // unlimited, as everywhere else.
    const maxUses = invite[DBSchema.invites.maxUses] as number | null;
    const uses = (invite[DBSchema.invites.uses] as number | null) ?? 0;
    if (maxUses !== null && maxUses > 0 && uses >= maxUses) {
      return CustomResponse.error(
        "Invite code has reached its maximum uses",
        EC.INVITE_EXHAUSTED,
      );
    }

    const serverId = invite[DBSchema.invites.serverId] as string;

    // Server name for the join UI (best-effort — not required to proceed).
    const { data: serverData } = await supabase
      .from(DBSchema.servers.tableName)
      .select(DBSchema.servers.name)
      .eq(DBSchema.servers.id, serverId)
      .maybeSingle();

    return CustomResponse.success({
      server_id: serverId,
      server_name: (serverData as Record<string, any> | null)?.[DBSchema.servers.name] ?? null,
    });
  } catch (err) {
    return CustomResponse.error(`Unexpected error: ${err}`, EC.UNEXPECTED_ERROR, err);
  }
});
