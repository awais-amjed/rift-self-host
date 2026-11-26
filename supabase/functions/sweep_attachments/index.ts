import "@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "@supabase/supabase-js";
import { corsHeaders } from "../_shared/cors.ts";
import { CustomResponse } from "../_shared/response.ts";
import * as EC from "../_shared/error_codes.ts";
import { authenticateToken, extractBearerToken, isAuthError } from "../_shared/auth.ts";
import { timingSafeEqual } from "@std/crypto/timing-safe-equal";

const supabase = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
);

/** How many blobs one call will remove. A backlog is drained by calling again. */
const BATCH = 1000;

/**
 * Removes the attachment blobs left behind. The retention settings are applied
 * by the hourly `rift-message-retention` job, not here (048).
 *
 * This exists because deleting a message frees almost nothing on its own.
 * `ciphertext` is capped at 16 KB, so the disk an operator worries about is
 * filled by attachments — and nothing in the database can delete one.
 * `storage.protect_delete()` refuses direct DELETE on `storage.objects` with
 * "Use the Storage API instead", so the sweep has to end somewhere holding the
 * service key. That is here.
 *
 * The database decides *what* to remove — `sweep_attachments()` returns
 * deleted messages' files on every run, and once a day everything nobody holds
 * (see the migrations). This function only carries out
 * the half SQL can't.
 *
 * The console calls it every few minutes, with the service key in the body
 * as `create_server` takes it (`sweepAttachmentsNow` in the console). Apps
 * before self-host 064 call it too, on server-ready, and any member still may:
 * it removes only unreferenced objects, so the worst a caller can do is
 * maintenance — and only once a minute.
 */
Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    if (!(await fromConsole(req))) {
      const token = extractBearerToken(req);
      const auth = await authenticateToken(supabase, token);
      if (isAuthError(auth)) return auth;
    }

    // A minute apart, whoever asks (`claim_attachment_sweep`): every app
    // calls this as it opens a server, and once a day a run reads every file.
    // Too soon is not a failure, just nothing to do yet.
    const { data: due, error: dueError } = await supabase.rpc("claim_attachment_sweep");
    if (dueError) {
      return CustomResponse.error("Error running the sweep", EC.DB_ERROR, dueError);
    }
    if (due !== true) {
      return CustomResponse.success({ swept: 0, more: false });
    }

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

/** Whether the body carries this stack's service key: the console's timer. */
async function fromConsole(req: Request): Promise<boolean> {
  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return false;
  }
  const provided = (body as { service_key?: unknown } | null)?.service_key;
  if (typeof provided !== "string" || provided.length === 0) return false;
  const encoder = new TextEncoder();
  const providedBytes = encoder.encode(provided);
  const expectedBytes = encoder.encode(Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "");
  return expectedBytes.byteLength > 0 &&
    providedBytes.byteLength === expectedBytes.byteLength &&
    timingSafeEqual(providedBytes, expectedBytes);
}
