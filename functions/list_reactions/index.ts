import "@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "@supabase/supabase-js";
import DBSchema from "../_shared/schema.ts";
import { corsHeaders } from "../_shared/cors.ts";
import { CustomResponse } from "../_shared/response.ts";
import * as EC from "../_shared/error_codes.ts";
import { authenticateToken, extractBearerToken, isAuthError } from "../_shared/auth.ts";
import { checkChannel } from "../_shared/chat.ts";

const supabase = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
);

const MAX_IDS = 200;

/**
 * Reactions for a set of messages (channel or server DM), aggregated per
 * message into `[{ emoji, count, mine }]`. The client calls this after loading
 * a page and whenever a reaction doorbell fires, then merges the result into
 * the messages already in state — so reaction changes never disturb scroll or
 * message content.
 *
 * Body: `{ scope: "channel"|"dm", channel_id?, peer_id?, message_ids: number[] }`.
 * Membership is enforced (channel or DM participation) and rows are filtered to
 * that channel/conversation, so a member can't probe reactions elsewhere.
 */
Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const { scope, channel_id, peer_id, message_ids } = await req.json();
    const token = extractBearerToken(req);

    const auth = await authenticateToken(supabase, token);
    if (isAuthError(auth)) return auth;

    if (!Array.isArray(message_ids) || message_ids.length === 0) {
      return CustomResponse.success({ reactions: {} });
    }
    const ids = message_ids
      .filter((v) => Number.isInteger(v))
      .slice(0, MAX_IDS);
    if (ids.length === 0) return CustomResponse.success({ reactions: {} });

    const R = DBSchema.messageReactions; // shared column names

    // Rows: [{ message_id, user_id, emoji }] filtered to the caller's scope.
    let rows: Record<string, any>[] = [];

    if (scope === "channel") {
      const channel = await checkChannel(supabase, channel_id, auth.serverId);
      if (channel instanceof Response) return channel;

      const { data, error } = await supabase
        .from(DBSchema.messageReactions.tableName)
        .select(
          `${R.messageId}, ${R.userId}, ${R.emoji},` +
          ` ${DBSchema.messages.tableName}!inner(${DBSchema.messages.channelId})`,
        )
        .in(R.messageId, ids);
      if (error) return CustomResponse.error("Error listing reactions", EC.DB_ERROR, error);
      rows = ((data ?? []) as Record<string, any>[]).filter((r) =>
        r[DBSchema.messages.tableName]?.[DBSchema.messages.channelId] === channel_id
      );
    } else if (scope === "dm") {
      if (!peer_id) {
        return CustomResponse.error("Missing required field: peer_id", EC.MISSING_FIELDS);
      }
      const m = DBSchema.dmMessages;
      const { data, error } = await supabase
        .from(DBSchema.dmMessageReactions.tableName)
        .select(
          `${R.messageId}, ${R.userId}, ${R.emoji},` +
          ` ${m.tableName}!inner(${m.senderId}, ${m.recipientId})`,
        )
        .in(R.messageId, ids);
      if (error) return CustomResponse.error("Error listing reactions", EC.DB_ERROR, error);
      rows = ((data ?? []) as Record<string, any>[]).filter((r) => {
        const dm = r[m.tableName] as Record<string, any> | null;
        if (!dm) return false;
        const s = dm[m.senderId];
        const rc = dm[m.recipientId];
        return (s === auth.userId && rc === peer_id) ||
          (s === peer_id && rc === auth.userId);
      });
    } else {
      return CustomResponse.error("Invalid scope", EC.MISSING_FIELDS);
    }

    // Aggregate: message_id -> emoji -> { count, mine }.
    const byMessage: Record<string, Record<string, { count: number; mine: boolean }>> = {};
    for (const row of rows) {
      const mid = String(row[R.messageId]);
      const emoji = row[R.emoji] as string;
      const bucket = (byMessage[mid] ??= {});
      const agg = (bucket[emoji] ??= { count: 0, mine: false });
      agg.count += 1;
      if (row[R.userId] === auth.userId) agg.mine = true;
    }

    const reactions: Record<string, { emoji: string; count: number; mine: boolean }[]> = {};
    for (const [mid, bucket] of Object.entries(byMessage)) {
      reactions[mid] = Object.entries(bucket).map(([emoji, agg]) => ({
        emoji,
        count: agg.count,
        mine: agg.mine,
      }));
    }

    return CustomResponse.success({ reactions });
  } catch (err) {
    return CustomResponse.error(`Unexpected error: ${err}`, EC.UNEXPECTED_ERROR, err);
  }
});
