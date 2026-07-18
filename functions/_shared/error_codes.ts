/**
 * Machine-readable error codes included in every error response.
 *
 * Keep this file in sync with `lib/data/enums/error_code.dart` on the
 * Flutter side — both use the same snake_case string values so that client
 * code can switch on `response.errorCode` instead of doing fragile
 * substring matches on the human-readable `error` message.
 */

// ── Token / session ───────────────────────────────────────────────────────────
export const TOKEN_MISSING   = "token_missing";   // token field absent in request
export const TOKEN_INVALID   = "token_invalid";   // token not found in DB
export const TOKEN_EXPIRED   = "token_expired";   // token TTL has passed
export const TOKEN_UNLINKED  = "token_unlinked";  // token row has no user_id
export const NO_SESSION      = "no_session";      // user exists but has no token row

// ── Challenge / auth flow ─────────────────────────────────────────────────────
export const CHALLENGE_INVALID = "challenge_invalid"; // nonce not found / already used
export const CHALLENGE_EXPIRED = "challenge_expired"; // nonce TTL has passed
export const SIGNATURE_INVALID = "signature_invalid"; // Ed25519 verification failed

// ── User ──────────────────────────────────────────────────────────────────────
export const USER_NOT_FOUND = "user_not_found";
export const USER_BANNED    = "user_banned";

// ── Server ────────────────────────────────────────────────────────────────────
export const SERVER_NOT_FOUND           = "server_not_found";
export const SERVER_KEY_INVALID         = "server_key_invalid";         // wrong service-role key
export const SERVER_CREDENTIALS_MISSING = "server_credentials_missing"; // LiveKit / seeding secret missing

// ── Channel ───────────────────────────────────────────────────────────────────
export const CHANNEL_NOT_FOUND     = "channel_not_found";
export const CHANNEL_NAME_DUPLICATE = "channel_name_duplicate";
export const CHANNEL_TYPE_INVALID  = "channel_type_invalid";
export const CHANNEL_WRONG_SERVER  = "channel_wrong_server"; // channel belongs to a different server

// ── Key rotation ──────────────────────────────────────────────────────────────
export const KEY_SAME   = "key_same";   // new key identical to old key
export const KEY_IN_USE = "key_in_use"; // new key already registered to another user

// ── Registration ──────────────────────────────────────────────────────────────
export const INVITE_INVALID   = "invite_invalid";
export const INVITE_EXHAUSTED = "invite_exhausted"; // max_uses reached
export const INVITE_EXPIRED   = "invite_expired";   // expires_at has passed
export const IDENTITY_TAKEN   = "identity_taken";   // public_key or stable_id already registered
export const USERNAME_TAKEN   = "username_taken";
export const INVALID_PUBLIC_KEY = "invalid_public_key"; // not valid base64 or wrong length
export const INVALID_STABLE_ID  = "invalid_stable_id";  // not valid base64 or wrong length

// ── Chat ──────────────────────────────────────────────────────────────────────
export const KEYRING_CONFLICT   = "keyring_conflict";   // key version already exists — refetch and re-wrap
export const ENVELOPE_INVALID   = "envelope_invalid";   // message envelope fields missing/oversized
export const CHAT_KEY_INVALID   = "chat_key_invalid";   // chat_public_key not valid base64 / wrong length

// ── Permissions ───────────────────────────────────────────────────────────────
export const PERMISSION_DENIED = "permission_denied";

// ── Generic ───────────────────────────────────────────────────────────────────
export const MISSING_FIELDS    = "missing_fields";
export const DB_ERROR          = "db_error";       // unexpected database error
export const UNEXPECTED_ERROR  = "unexpected_error";

