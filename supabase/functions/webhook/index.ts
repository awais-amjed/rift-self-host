import "@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "@supabase/supabase-js";
import { corsHeaders } from "../_shared/cors.ts";
import { CustomResponse } from "../_shared/response.ts";
import * as EC from "../_shared/error_codes.ts";

/**
 * Incoming webhook — the one endpoint here that anybody may call.
 *
 *   POST /functions/v1/webhook/<secret>
 *   { "text": "build passed" }          (also accepts "content", or a raw body)
 *
 * **Deploy with `--no-verify-jwt`.** The whole point of a webhook is that the
 * caller cannot log in: GitHub holds no Rift identity and never will. The URL
 * is the credential, which is why `post_webhook_message` hashes it, rate-limits
 * it, and answers every kind of failure the same way.
 *
 * This function is deliberately thin. The lookup, the rate check and the insert
 * are one statement inside the database (migration 013) so nothing can sit
 * between them, and so the rule survives the next thing that learns to write a
 * message. All that is left out here is the part only an edge function can do:
 * being reachable without a JWT, and ringing the doorbell afterwards.
 *
 * `content` is accepted alongside `text` on purpose. It is the field Discord's
 * webhooks use, so anything already configured to post to one — a CI job, a
 * monitoring alert, a `curl` in a cron — works against this by changing the URL
 * and nothing else.
 */

const supabase = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
);

/** Every refusal a caller can provoke, and the status it deserves. */
const FAILURES: Record<string, { status: number; message: string }> = {
  no_such_webhook: { status: 404, message: "Unknown webhook" },
  empty: { status: 400, message: "Message is empty" },
  too_long: { status: 400, message: "Message is too long" },
  rate_limited: { status: 429, message: "Too many posts — slow down" },
};

/**
 * The secret is the last path segment. Read it from the end rather than by
 * index: the runtime and the gateway do not agree on how much of
 * `/functions/v1/webhook/…` is still on the path by the time it arrives here.
 */
function secretFrom(req: Request): string | null {
  const parts = new URL(req.url).pathname.split("/").filter(Boolean);
  const last = parts[parts.length - 1];
  if (!last || last === "webhook") return null;
  return last;
}

/**
 * Pull the message text out of whatever the caller sent.
 *
 * A raw non-JSON body is accepted as the text itself, because plenty of things
 * that can `curl` cannot easily build JSON, and refusing them would be a
 * refusal on a technicality.
 */
async function textFrom(req: Request): Promise<string | null> {
  const raw = await req.text();
  if (!raw) return null;
  try {
    const body = JSON.parse(raw);
    if (typeof body === "string") return body;
    const value = body?.text ?? body?.content;
    return typeof value === "string" ? value : null;
  } catch {
    return raw;
  }
}

/**
 * Tell anyone with the channel open that something arrived.
 *
 * Best-effort, and never allowed to fail the request: the message is already
 * stored by the time this runs, every client re-reads on open, and the unread
 * badge comes from the row itself. A webhook that got a 500 because a doorbell
 * did not ring would be retried by its caller and post the message twice.
 */
async function ringDoorbell(channelId: string): Promise<void> {
  try {
    await supabase.channel(`chat:${channelId}`).send({
      type: "broadcast",
      event: "new_message",
      payload: {},
    });
  } catch (err) {
    console.error("[webhook] doorbell failed (message was still stored):", err);
  }
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  if (req.method !== "POST") {
    return CustomResponse.error("Use POST", EC.MISSING_FIELDS, undefined, 405);
  }

  try {
    const secret = secretFrom(req);
    if (!secret) {
      return CustomResponse.error(
        "Missing webhook secret in the URL",
        EC.MISSING_FIELDS,
        undefined,
        404,
      );
    }

    const text = await textFrom(req);
    if (text === null) {
      return CustomResponse.error(
        "Missing message text",
        EC.MISSING_FIELDS,
        undefined,
        400,
      );
    }

    const { data, error } = await supabase.rpc("post_webhook_message", {
      p_secret: secret,
      p_text: text,
    });

    if (error) {
      return CustomResponse.error("Error posting message", EC.DB_ERROR, error, 500);
    }

    const reason = (data as Record<string, unknown> | null)?.reason as string;
    if (reason !== "ok") {
      const failure = FAILURES[reason] ??
        { status: 400, message: "Could not post that" };
      // Deliberately the same shape for every refusal. A caller holding a wrong
      // secret learns that it is wrong and nothing else — not whether the
      // webhook exists, not which channel it would have reached.
      return CustomResponse.error(failure.message, reason, undefined, failure.status);
    }

    const row = data as Record<string, string>;
    await ringDoorbell(row.channel_id);

    return CustomResponse.success({ message_id: row.message_id });
  } catch (err) {
    return CustomResponse.error(`Unexpected error: ${err}`, EC.UNEXPECTED_ERROR, err, 500);
  }
});
