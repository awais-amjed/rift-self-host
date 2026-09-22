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

// ── Auth flow ─────────────────────────────────────────────────────────────────
export const SIGNATURE_INVALID = "signature_invalid"; // Ed25519 verification failed

// ── User ──────────────────────────────────────────────────────────────────────
export const USER_NOT_FOUND    = "user_not_found";
export const USER_BANNED       = "user_banned";
export const USER_NOT_IN_VOICE = "user_not_in_voice"; // nothing to move: they're not in a call

// ── Server ────────────────────────────────────────────────────────────────────
export const SERVER_NOT_FOUND           = "server_not_found";
export const SERVER_KEY_INVALID         = "server_key_invalid";         // wrong service-role key
export const SERVER_CREDENTIALS_MISSING = "server_credentials_missing"; // LiveKit / seeding secret missing

// ── Channel ───────────────────────────────────────────────────────────────────
export const MESSAGE_NOT_FOUND     = "message_not_found";
export const CHANNEL_NOT_FOUND     = "channel_not_found";
export const CHANNEL_NAME_DUPLICATE = "channel_name_duplicate";
export const CHANNEL_TYPE_INVALID  = "channel_type_invalid";

// ── Key rotation ──────────────────────────────────────────────────────────────
// A bot asked for a voice token before any member sealed it a media key.
// Retryable, and it clears as soon as a member is in the channel.
export const KEY_NOT_READY = "key_not_ready";

// ── Registration ──────────────────────────────────────────────────────────────
export const INVITE_INVALID   = "invite_invalid";
export const INVITE_EXHAUSTED = "invite_exhausted"; // max_uses reached
export const INVITE_EXPIRED   = "invite_expired";   // expires_at has passed
export const IDENTITY_TAKEN   = "identity_taken";   // public_key or stable_id already registered
export const USERNAME_TAKEN   = "username_taken";
export const USERNAME_INVALID = "username_invalid"; // outside the mention parser's alphabet
export const INVALID_PUBLIC_KEY = "invalid_public_key"; // not valid base64 or wrong length
export const INVALID_STABLE_ID  = "invalid_stable_id";  // not valid base64 or wrong length

// ── Chat ──────────────────────────────────────────────────────────────────────
export const KEYRING_CONFLICT   = "keyring_conflict";   // key version already exists — refetch and re-wrap
export const ENVELOPE_INVALID   = "envelope_invalid";   // message envelope fields missing/oversized
export const CHAT_KEY_INVALID   = "chat_key_invalid";   // chat_public_key not valid base64 / wrong length

// ── Permissions ───────────────────────────────────────────────────────────────
export const PERMISSION_DENIED = "permission_denied";

// ── Operator limits ───────────────────────────────────────────────────────────
export const LIMIT_INVALID = "limit_invalid"; // a limit is negative, or the size cap is out of range
export const VOICE_CHANNEL_FULL = "voice_channel_full"; // max_voice_participants reached
export const SERVER_FULL = "server_full"; // max_members reached (029)

// ── Generic ───────────────────────────────────────────────────────────────────
export const MISSING_FIELDS    = "missing_fields";
export const DB_ERROR          = "db_error";       // unexpected database error
export const UNEXPECTED_ERROR  = "unexpected_error";

