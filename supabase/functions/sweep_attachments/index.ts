import "@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "@supabase/supabase-js";
import { corsHeaders } from "../_shared/cors.ts";
import { CustomResponse } from "../_shared/response.ts";
import * as EC from "../_shared/error_codes.ts";
import { authenticateToken, extractBearerToken, isAuthError } from "../_shared/auth.ts";

const supabase = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
);

/** How many blobs one call will remove. A backlog is drained by calling again. */
const BATCH = 1000;

/**
 * Applies the server's retention settings and removes the attachment blobs left
 * behind.
 *
 * This exists because deleting a message frees almost nothing on its own.
 * `ciphertext` is capped at 16 KB, so the disk an operator worries about is
 * filled by attachments — and nothing in the database can delete one.
 * `storage.protect_delete()` refuses direct DELETE on `storage.objects` with
 * "Use the Storage API instead", so the sweep has to end somewhere holding the
 * service key. That is here.
 *
 * The database decides *what* to remove — `sweep_attachments()` runs the
 * retention pass and returns the blobs whose messages are gone, found without
 * any message→blob linkage (see the migration). This function only carries out
 * the half SQL can't.
 *
 * Any member may call it, the way any member may call `sweep_channel_keys`:
 * it removes only unreferenced objects, so the worst a caller can do is
 * maintenance. Clients run it on server-ready.
 */
Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const token = extractBearerToken(req);
    const auth = await authenticateToken(supabase, token);
    if (isAuthError(auth)) return auth;

    const { data, error } = await supabase.rpc("sweep_attachments", { p_limit: BATCH });
    if (error) {
      return CustomResponse.error("Error running the sweep", EC.DB_ERROR, error);
    }

    const orphans = ((data as Record<string, unknown> | null)?.orphans ?? []) as Array<
      { bucket: string; name: string }
    >;
    if (orphans.length === 0) {
      return CustomResponse.success({ swept: 0, more: false });
    }

    // Each server owns its own bucket, so a batch can span
    // several of them on a project hosting more than one server.
    const byBucket = new Map<string, string[]>();
    for (const orphan of orphans) {
      const names = byBucket.get(orphan.bucket) ?? [];
      names.push(orphan.name);
      byBucket.set(orphan.bucket, names);
    }

    for (const [bucket, names] of byBucket) {
      const { error: removeError } = await supabase.storage.from(bucket).remove(names);
      if (removeError) {
        return CustomResponse.error("Error removing attachments", EC.DB_ERROR, removeError);
      }
    }

    // `more` tells the caller the batch was full and another pass has work. A
    // client that ignores it loses nothing — the next server-ready picks it up.
    return CustomResponse.success({ swept: orphans.length, more: orphans.length === BATCH });
  } catch (error) {
    return CustomResponse.error("Unexpected error", EC.UNEXPECTED_ERROR, error);
  }
});
