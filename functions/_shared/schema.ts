const DBSchema = {
  servers: {
    tableName: "servers",
    id: "id",
    createdAt: "created_at",
    name: "name",
    iconUrl: "icon_url",
    livekitUrl: "livekit_url",
    // Operator limits (migration 007). Both sweeps default to 0 = off; the
    // attachment cap is a size and therefore has a real default. There is no
    // daily message quota — a rate limit does not bound storage.
    maxAttachmentBytes: "max_attachment_bytes",
    messageRetentionDays: "message_retention_days",
    messageHistoryCap: "message_history_cap",
  },
  // Split out of `servers` so the rest of that row can be read directly by
  // members under RLS. This table has no grant and no policy: the service role
  // is the only thing that can reach it.
  serverSecrets: {
    tableName: "server_secrets",
    serverId: "server_id",
    livekitApiKey: "livekit_api_key",
    livekitSecretKey: "livekit_secret_key",
  },
  users: {
    tableName: "users",
    id: "id",
    createdAt: "created_at",
    serverId: "server_id",
    username: "username",
    displayName: "display_name",
    publicKey: "public_key",
    stableId: "stable_id",
    isBanned: "is_banned",
    isServerAdmin: "is_server_admin",
    isChannelManager: "is_channel_manager",
    canCreateTokens: "can_create_tokens",
    isMuted: "is_muted",
    isDeafened: "is_deafened",
    chatPublicKey: "chat_public_key",
    avatarPath: "avatar_path",
  },
  channelKeyring: {
    tableName: "channel_keyring",
    id: "id",
    createdAt: "created_at",
    channelId: "channel_id",
    keyVersion: "key_version",
    userId: "user_id",
    wrappedBy: "wrapped_by",
    ephemeralPublicKey: "ephemeral_public_key",
    ciphertext: "ciphertext",
    nonce: "nonce",
  },
  channels: {
    tableName: "channels",
    id: "id",
    createdAt: "created_at",
    serverId: "server_id",
    name: "name",
    channelType: "channel_type",
    // Per-channel retention overrides. NULL inherits the server's number;
    // 0 explicitly opts this channel out of a server-wide sweep.
    retentionDays: "retention_days",
    historyCap: "history_cap",
  },
  invites: {
    tableName: "invites",
    id: "id",
    createdAt: "created_at",
    serverId: "server_id",
    code: "code",
    isServerAdmin: "is_server_admin",
    isChannelManager: "is_channel_manager",
    canCreateTokens: "can_create_tokens",
    maxUses: "max_uses",
    uses: "uses",
    expiresAt: "expires_at",
  },
};

export default DBSchema;
