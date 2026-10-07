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

/**
 * Key-distribution sweep (Phase 2, ARCHITECTURE.md §4): one call that lists
 * every channel where the caller can do healing work —
 * - channels whose current key version the caller holds while other eligible
 *   members lack an entry (returns the caller's sealed key + the missing
 *   members' chat public keys),
 * - channels with no key at all (`key_version: 0`) so the caller can
 *   bootstrap v1, and
 * - channels that owe a rotation, so the caller can mint the next version for
 *   the people still entitled to one, and
 * - older versions the caller holds and an eligible member lacks, so somebody
 *   who joined after a rotation can read what was said before it.
 * Clients run this on launch/server-select and when the key-sweep doorbell
 * rings, so a new member gets access as soon as any member is online.
 *
 * **Voice channels are included**, and used not to be — they held no messages,
 * so they held no keys and there was nothing to sweep. Calls are now encrypted
 * with the channel's own key (ARCHITECTURE.md §5), which makes the omission a
 * hole rather than an optimisation: without it a banned member's voice key is
 * never rotated away from them, and a new member is only ever keyed by whoever
 * happens to join a call next.
 *
 * The work is found by `channel_key_work` in the database (012), not here. This
 * used to read the server's whole keyring and membership through PostgREST,
 * which answers at most 1000 rows and drops the rest silently, so a server of
 * any size was swept from part of its keyring. The answer is one JSON value:
 * at most 500 entries to seal, `more` when some were held back, and each
 * channel's work handed to one member at a time.
 *
 * Eligibility still comes from `channel_eligible_members`, the same answer the
 * row-level security policies give, which this service-role call bypasses.
 */
Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const token = extractBearerToken(req);
    const auth = await authenticateToken(supabase, token);
    if (isAuthError(auth)) return auth;

    const { data, error } = await supabase.rpc("channel_key_work", {
      p_user: auth.userId,
    });
    if (error) {
      return CustomResponse.error("Error finding key work", EC.DB_ERROR, error);
    }
    const answer = (data ?? {}) as Record<string, unknown>;
    return CustomResponse.success({
      work: answer.work ?? [],
      more: answer.more === true,
    });
  } catch (err) {
    return CustomResponse.error(`Unexpected error: ${err}`, EC.UNEXPECTED_ERROR, err);
  }
});
