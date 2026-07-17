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

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const { old_public_key, new_public_key, nonce, signature, host: clientHost, server_id } = await req.json();

    if (!old_public_key || !new_public_key || !nonce || !signature || !server_id) {
      return CustomResponse.error(
        "Missing required fields: old_public_key, new_public_key, nonce, signature, server_id",
        EC.MISSING_FIELDS,
      );
    }

    if (old_public_key === new_public_key) {
      return CustomResponse.error("New public key must differ from the old one", EC.KEY_SAME);
    }

    // Validate new_public_key: must be valid base64 encoding of exactly 32 bytes (Ed25519).
    // A malformed key would be stored successfully but make the account permanently
    // inaccessible, since verify_challenge would never be able to import it.
    let newPubKeyBytes: Uint8Array;
    try {
      newPubKeyBytes = Uint8Array.from(atob(new_public_key), (c) => c.charCodeAt(0));
    } catch {
      return CustomResponse.error("Invalid new_public_key: not valid base64", EC.INVALID_PUBLIC_KEY);
    }
    if (newPubKeyBytes.length !== 32) {
      return CustomResponse.error(
        `Invalid new_public_key: expected 32 bytes, got ${newPubKeyBytes.length}`,
        EC.INVALID_PUBLIC_KEY,
      );
    }

    // 1. Fetch and burn the rotation nonce — prevents replay attacks.
    // The client obtains this nonce via get_challenge (same flow as login).
    const { data: challengeData, error: challengeError } = await supabase
      .from(DBSchema.authChallenges.tableName)
      .delete()
      .eq(DBSchema.authChallenges.nonce, nonce)
      .eq(DBSchema.authChallenges.publicKey, old_public_key)
      .select()
      .maybeSingle();

    if (challengeError || !challengeData) {
      return CustomResponse.error("Invalid or expired rotation challenge", EC.CHALLENGE_INVALID, challengeError);
    }

    const expiresAt = new Date((challengeData as Record<string, any>)[DBSchema.authChallenges.expiresAt]);
    if (expiresAt < new Date()) {
      return CustomResponse.error("Rotation challenge has expired", EC.CHALLENGE_EXPIRED);
    }

    // 2. Look up user by old public key scoped to this server
    const { data: userData, error: userError } = await supabase
      .from(DBSchema.users.tableName)
      .select(`${DBSchema.users.id}, ${DBSchema.users.isBanned}`)
      .eq(DBSchema.users.serverId, server_id)
      .eq(DBSchema.users.publicKey, old_public_key)
      .single();

    if (userError || !userData) {
      return CustomResponse.error("User not found", EC.USER_NOT_FOUND, userError);
    }

    const userRecord = userData as Record<string, any>;

    if (userRecord[DBSchema.users.isBanned]) {
      return CustomResponse.error("User is banned", EC.USER_BANNED);
    }

    // 3. Verify the rotation signature.
    // Use the client-supplied host (most reliable — not affected by reverse
    // proxy Header rewrites). Falls back to new URL(req.url).hostname.
    const host: string = clientHost ?? new URL(req.url).hostname;
    // Nonce binds the signature to this specific server-issued challenge,
    // preventing replay attacks even if the message is intercepted in transit.
    const message = `rotate:${new_public_key}@${nonce}@${host}`;
    const messageBytes = new TextEncoder().encode(message);

    const oldPubKeyBytes = Uint8Array.from(atob(old_public_key), (c) =>
      c.charCodeAt(0),
    );
    const signatureBytes = Uint8Array.from(atob(signature), (c) =>
      c.charCodeAt(0),
    );

    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      oldPubKeyBytes,
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

    // 4. Ensure the new public key isn't already in use on this server
    const { data: existingUser } = await supabase
      .from(DBSchema.users.tableName)
      .select(DBSchema.users.id)
      .eq(DBSchema.users.serverId, server_id)
      .eq(DBSchema.users.publicKey, new_public_key)
      .maybeSingle();

    if (existingUser) {
      return CustomResponse.error("New public key is already in use", EC.KEY_IN_USE);
    }

    // 5. Update the user's public key
    const { error: updateError } = await supabase
      .from(DBSchema.users.tableName)
      .update({ [DBSchema.users.publicKey]: new_public_key })
      .eq(DBSchema.users.id, userRecord[DBSchema.users.id]);

    if (updateError) {
      return CustomResponse.error("Error updating public key", EC.DB_ERROR, updateError);
    }

    // 6. Invalidate the existing session token.
    // The old key may have been compromised — any session token issued under it
    // must no longer be accepted. Deleting the row forces a fresh verify_challenge
    // handshake signed with the new key before the client can make API calls again.
    const { error: tokenDeleteError } = await supabase
      .from(DBSchema.tokens.tableName)
      .delete()
      .eq(DBSchema.tokens.userId, userRecord[DBSchema.users.id]);

    if (tokenDeleteError) {
      return CustomResponse.error("Error invalidating session token", EC.DB_ERROR, tokenDeleteError);
    }

    return CustomResponse.success({
      message: "Key rotated successfully. Please re-authenticate with your new key.",
      user_id: userRecord[DBSchema.users.id],
    });
  } catch (err) {
    return CustomResponse.error(`Unexpected error: ${err}`, EC.UNEXPECTED_ERROR, err);
  }
});
