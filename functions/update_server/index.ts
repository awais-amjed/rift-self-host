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

/** Storage refuses an object larger than this, so a cap past it can't be met. */
const MAX_ATTACHMENT_CEILING = 524288000; // 500 MB

/**
 * The operator limits from migration 007, as (request field → column) pairs.
 *
 * They are validated together rather than one `if` each because they share one
 * rule: an integer, never negative, and 0 means "no limit". Only the size cap
 * has an upper bound, because only it has to be a size Storage will accept.
 */
const LIMIT_FIELDS = [
  { key: "max_attachment_bytes", column: DBSchema.servers.maxAttachmentBytes, min: 1, max: MAX_ATTACHMENT_CEILING },
  { key: "default_channel_daily_quota", column: DBSchema.servers.defaultChannelDailyQuota, min: 0 },
  { key: "dm_daily_quota", column: DBSchema.servers.dmDailyQuota, min: 0 },
  { key: "message_retention_days", column: DBSchema.servers.messageRetentionDays, min: 0 },
  { key: "message_history_cap", column: DBSchema.servers.messageHistoryCap, min: 0 },
] as const;

/** Every column this endpoint reads back, so the client's copy stays whole. */
const SERVER_SELECT = [
  DBSchema.servers.name,
  DBSchema.servers.iconUrl,
  DBSchema.servers.livekitUrl,
  ...LIMIT_FIELDS.map((f) => f.column),
].join(", ");

/**
 * Push the largest configured cap onto the shared `chat-attachments` bucket.
 *
 * The column on `servers` is what the client reads to refuse a file before
 * uploading it; this is what makes the cap true for a client that doesn't
 * bother asking. It has to be the MAX across servers because one Supabase
 * project can host several of them and they share the bucket — a stricter
 * server's limit is still enforced, by its own trigger-free path: the client
 * check plus the fact that nobody else's messages reference its blobs.
 *
 * Best-effort on purpose. A bucket that won't update is a weaker ceiling, not
 * a reason to refuse an admin's settings change.
 */
async function mirrorAttachmentCap(): Promise<void> {
  const { data, error } = await supabase
    .from(DBSchema.servers.tableName)
    .select(DBSchema.servers.maxAttachmentBytes);
  if (error || !data?.length) return;

  const ceiling = Math.max(
    ...data.map((r) => Number((r as Record<string, unknown>)[DBSchema.servers.maxAttachmentBytes] ?? 0)),
  );
  if (!Number.isFinite(ceiling) || ceiling <= 0) return;

  await supabase.storage.updateBucket("chat-attachments", { fileSizeLimit: ceiling });
}

/** A `servers` row as the client reads it — snake_case, limits included. */
function toServerResponse(row: Record<string, any> | null) {
  if (!row) return row;
  const out: Record<string, unknown> = {
    name: row[DBSchema.servers.name],
    icon_url: row[DBSchema.servers.iconUrl],
    livekit_url: row[DBSchema.servers.livekitUrl],
  };
  for (const field of LIMIT_FIELDS) out[field.key] = row[field.column];
  return out;
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const body = await req.json();
    const { name, icon_url, livekit_url, livekit_api_key, livekit_secret_key } = body;
    const token = extractBearerToken(req);

    // Authenticate
    const auth = await authenticateToken(supabase, token);
    if (isAuthError(auth)) return auth;

    const limitsGiven = LIMIT_FIELDS.filter((f) => body[f.key] !== undefined);

    // Check if at least one field to update is provided
    if (
      !name && icon_url === undefined && !livekit_url && !livekit_api_key &&
      !livekit_secret_key && limitsGiven.length === 0
    ) {
      return CustomResponse.error(
        "At least one field to update must be provided: name, icon_url, livekit_url, " +
          "livekit_api_key, livekit_secret_key, or one of the server limits",
        EC.MISSING_FIELDS,
      );
    }

    // Validated here as well as by the CHECK constraint, so an admin gets a
    // sentence instead of a Postgres constraint name.
    for (const field of limitsGiven) {
      const value = body[field.key];
      if (!Number.isInteger(value) || value < field.min || ("max" in field && value > field.max)) {
        return CustomResponse.error(
          `${field.key} must be a whole number of at least ${field.min}` +
            ("max" in field ? ` and at most ${field.max}` : " (0 means no limit)"),
          EC.LIMIT_INVALID,
        );
      }
    }

    // Check permission
    if (!auth.isServerAdmin) {
      return CustomResponse.error("Unauthorized: Only server admins can update server details", EC.PERMISSION_DENIED);
    }

    // Build update object dynamically
    const updateData: Record<string, unknown> = {};
    if (name) {
      updateData[DBSchema.servers.name] = name;
    }
    if (icon_url !== undefined) {
      updateData[DBSchema.servers.iconUrl] = icon_url;
    }
    if (livekit_url) {
      updateData[DBSchema.servers.livekitUrl] = livekit_url;
    }
    for (const field of limitsGiven) {
      updateData[field.column] = body[field.key];
    }
    // Credentials live in server_secrets, so they are a separate write. This
    // endpoint exists for them: name and icon ride along rather than splitting
    // one settings dialog across two transports.
    const secretData: Record<string, unknown> = {};
    if (livekit_api_key) {
      secretData[DBSchema.serverSecrets.livekitApiKey] = livekit_api_key;
    }
    if (livekit_secret_key) {
      secretData[DBSchema.serverSecrets.livekitSecretKey] = livekit_secret_key;
    }
    if (Object.keys(secretData).length > 0) {
      const { error: secretsError } = await supabase
        .from(DBSchema.serverSecrets.tableName)
        .update(secretData)
        .eq(DBSchema.serverSecrets.serverId, auth.serverId);
      if (secretsError) {
        return CustomResponse.error("Error updating server credentials", EC.DB_ERROR, secretsError);
      }
    }

    if (Object.keys(updateData).length === 0) {
      const { data: current } = await supabase
        .from(DBSchema.servers.tableName)
        .select(SERVER_SELECT)
        .eq(DBSchema.servers.id, auth.serverId)
        .single();
      return CustomResponse.success(toServerResponse(current as Record<string, any> | null));
    }

    // Update server details
    const { data, error } = await supabase
      .from(DBSchema.servers.tableName)
      .update(updateData)
      .eq(DBSchema.servers.id, auth.serverId)
      .select(SERVER_SELECT)
      .single();

    if (error) {
      return CustomResponse.error("Error updating server", EC.DB_ERROR, error);
    }
    if (!data) {
      return CustomResponse.error("Server not found", EC.SERVER_NOT_FOUND);
    }

    // After the row, not before: the bucket should follow what was actually
    // saved, and a rejected update must not move the ceiling.
    if (limitsGiven.some((f) => f.key === "max_attachment_bytes")) {
      await mirrorAttachmentCap();
    }

    return CustomResponse.success(toServerResponse(data as Record<string, any>));
  } catch (error) {
    return CustomResponse.error("Unexpected error", EC.UNEXPECTED_ERROR, error);
  }
});
