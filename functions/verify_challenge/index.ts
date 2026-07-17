import "@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "@supabase/supabase-js";
import DBSchema from "../_shared/schema.ts";
import { corsHeaders } from "../_shared/cors.ts";
import { CustomResponse } from "../_shared/response.ts";
import * as EC from "../_shared/error_codes.ts";
import { fetchServerContext } from "../_shared/server_context.ts";
import { generateSecureToken } from "../_shared/token_utils.ts";

const supabase = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
);

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const { public_key, nonce, signature, host: clientHost, server_id } = await req.json();

    if (!public_key || !nonce || !signature || !server_id) {
      return CustomResponse.error(
        "Missing required fields: public_key, nonce, signature, server_id",
        EC.MISSING_FIELDS,
      );
    }

    // 1. Fetch and burn the nonce — prevents replay attacks
    const { data: challengeData, error: challengeError } = await supabase
      .from(DBSchema.authChallenges.tableName)
      .delete()
      .eq(DBSchema.authChallenges.nonce, nonce)
      .eq(DBSchema.authChallenges.publicKey, public_key)
      .select()
      .maybeSingle();

    if (challengeError || !challengeData) {
      return CustomResponse.error("Invalid or expired challenge", EC.CHALLENGE_INVALID, challengeError);
    }

    const challengeRecord = challengeData as Record<string, any>;

    // Check TTL
    const expiresAt = new Date(
      challengeRecord[DBSchema.authChallenges.expiresAt],
    );
    if (expiresAt < new Date()) {
      return CustomResponse.error("Challenge has expired", EC.CHALLENGE_EXPIRED);
    }

    // 2. Reconstruct the message: "nonce@host"
    //
    // The client sends the hostname it used for key derivation in the request
    // body. This is the most reliable source — it doesn't depend on the Host
    // header (which reverse proxies may rewrite to an internal address) or
    // the SUPABASE_URL env var (which points to an internal Docker hostname
    // in local dev).
    //
    // Falls back to new URL(req.url).hostname for older clients that don't
    // yet send the host field.
    const host: string =
      clientHost ?? new URL(req.url).hostname;
    const message = `${nonce}@${host}`;
    const messageBytes = new TextEncoder().encode(message);

    // 3. Decode public key and signature (base64)
    const publicKeyBytes = Uint8Array.from(atob(public_key), (c) =>
      c.charCodeAt(0),
    );
    const signatureBytes = Uint8Array.from(atob(signature), (c) =>
      c.charCodeAt(0),
    );

    // 4. Verify Ed25519 signature
    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      publicKeyBytes,
      { name: "Ed25519" },
      false,
      ["verify"],
    );

    const valid = await crypto.subtle.verify(
      "Ed25519",
      cryptoKey,
      signatureBytes,
      messageBytes,
    );

    if (!valid) {
      return CustomResponse.error("Invalid signature", EC.SIGNATURE_INVALID);
    }

    // 5. Look up user by public key scoped to this server
    const { data: userData, error: userError } = await supabase
      .from(DBSchema.users.tableName)
      .select(`${DBSchema.users.id}, ${DBSchema.users.isBanned}, ${DBSchema.users.serverId}`)
      .eq(DBSchema.users.serverId, server_id)
      .eq(DBSchema.users.publicKey, public_key)
      .single();

    if (userError || !userData) {
      return CustomResponse.error("User not found", EC.USER_NOT_FOUND, userError);
    }

    const userRecord = userData as Record<string, any>;

    if (userRecord[DBSchema.users.isBanned]) {
      return CustomResponse.error("User is banned", EC.USER_BANNED);
    }

    const user_id = userRecord[DBSchema.users.id];

    // 6. Find or re-create the user's auth token.
    const { data: tokenData, error: tokenError } = await supabase
      .from(DBSchema.tokens.tableName)
      .select(`${DBSchema.tokens.token}, ${DBSchema.tokens.serverId}`)
      .eq(DBSchema.tokens.userId, user_id)
      .maybeSingle();

    let tokenValue: string;
    let token_server_id: string;

    if (!tokenError && tokenData) {
      // Token exists — refresh its TTL.
      const tokenRecord = tokenData as Record<string, any>;
      tokenValue = tokenRecord[DBSchema.tokens.token];
      token_server_id = tokenRecord[DBSchema.tokens.serverId];

      // 7. Refresh the token's TTL — every successful handshake extends the session by 1 hour
      const newExpiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString();
      await supabase
        .from(DBSchema.tokens.tableName)
        .update({ [DBSchema.tokens.expiresAt]: newExpiresAt })
        .eq(DBSchema.tokens.token, tokenValue);
    } else {
      // Token was deleted — re-issue a fresh one using the server_id from the request.
      token_server_id = server_id;

      tokenValue = generateSecureToken();
      const tokenExpiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString();

      // Use upsert so that a concurrent verify_challenge for the same user
      // doesn't race-insert a second token row — the UNIQUE(user_id) constraint
      // on tokens ensures at most one token per user.
      const { error: insertError } = await supabase
        .from(DBSchema.tokens.tableName)
        .upsert({
          [DBSchema.tokens.serverId]: server_id,
          [DBSchema.tokens.token]: tokenValue,
          [DBSchema.tokens.userId]: user_id,
          [DBSchema.tokens.expiresAt]: tokenExpiresAt,
        }, { onConflict: DBSchema.tokens.userId });

      if (insertError) {
        return CustomResponse.error(
          `Error re-creating auth token: ${JSON.stringify(insertError)}`,
          EC.DB_ERROR,
          insertError,
        );
      }
    }

    // 8. Fetch full server context
    const context = await fetchServerContext(supabase, {
      serverId: token_server_id,
      tokenValue: tokenValue,
      userId: user_id,
    });

    if (context instanceof Response) return context;

    return CustomResponse.success(context);
  } catch (err) {
    return CustomResponse.error(`Unexpected error: ${err}`, EC.UNEXPECTED_ERROR, err);
  }
});
