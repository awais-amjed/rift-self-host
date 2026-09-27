const DBSchema = {
  servers: {
    tableName: "servers",
    id: "id",
    createdAt: "created_at",
    name: "name",
    iconUrl: "icon_url",
    livekitUrl: "livekit_url",
    // Operator limits. Both sweeps default to 0 = off; the
    // attachment cap is a size and therefore has a real default. There is no
    // daily message quota — a rate limit does not bound storage.
    maxAttachmentBytes: "max_attachment_bytes",
    messageRetentionDays: "message_retention_days",
    messageHistoryCap: "message_history_cap",
    // DM overrides. Nullable like the channel-level columns,
    // because they override rather than set the base case: NULL inherits the
    // two above, 0 opts DMs out of a server-wide sweep.
    dmRetentionDays: "dm_retention_days",
    dmHistoryCap: "dm_history_cap",
    // What a call may cost the operator. Both 0 = off. The
    // participant cap is enforced here, by get_channel_token; the share cap
    // is a number the client keeps, because a LiveKit token cannot carry a
    // bitrate.
    maxVoiceParticipants: "max_voice_participants",
    maxShareMbps: "max_share_mbps",
    // How large the place may get. Both 0 = off, and both
    // are real walls: one way to become a member, one way for bytes to
    // arrive, and the database owns each.
    maxMembers: "max_members",
    maxStorageBytes: "max_storage_bytes",
    // How many people one member may start a DM with in an hour. 0 = off.
    // Enforced by the database's DM gate; admins are exempt.
    dmOpeningsPerHour: "dm_openings_per_hour",
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
    // A program, not a person. Bots are filtered out of every
    // key-distribution list below; the database refuses them a keyring entry
    // regardless, so these filters save a round trip rather than enforce a rule.
    isBot: "is_bot",
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
    // Which LiveKit region calls here are pinned to. NULL is automatic.
    livekitNodeId: "livekit_node_id",
  },
  // Where each member's phones can be reached, and the credential this server
  // rings them over. `push_config` has no grant and no policy:
  // the ring triggers read it as SECURITY DEFINER and no session can.
  deviceTokens: {
    tableName: "device_tokens",
    token: "token",
    userId: "user_id",
    platform: "platform",
    createdAt: "created_at",
    updatedAt: "updated_at",
  },
  pushConfig: {
    tableName: "push_config",
    serverId: "server_id",
    endpoint: "endpoint",
    relayId: "relay_id",
    secret: "secret",
    updatedAt: "updated_at",
  },
  invites: {
    tableName: "invites",
    id: "id",
    createdAt: "created_at",
    serverId: "server_id",
    code: "code",
    roleId: "role_id",
    maxUses: "max_uses",
    uses: "uses",
    expiresAt: "expires_at",
  },
};

export default DBSchema;
