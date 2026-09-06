/**
 * The servers on this stack, listed and created from the console.
 *
 * Creating a server needs four values — the service key, the LiveKit URL, and
 * LiveKit's key and secret — and the app asks for all four because it has no
 * way to know them. The console does: it generated every one of them. So this
 * exists to make that dialog unnecessary, and to stop the most sensitive
 * credential the stack has taking a trip through somebody's clipboard for no
 * reason.
 *
 * What comes back is an invite link, which is the only part of the exchange it
 * is safe to paste anywhere.
 */
import { FIELD_SEPARATOR, literal, type PostgresTarget, queryRows } from "./postgres.ts";
import { setting } from "./env_file.ts";
import { localPublicUrl, type LocalTesting, SIGNALLING_PORT } from "./local_testing.ts";
import { livekitUrlFor, provisionServer } from "./setup/provision.ts";

/** A server as the dashboard lists one. */
export interface ServerSummary {
  id: string;
  name: string;
  memberCount: number;
  channelCount: number;
  createdAt: string;
}

/** Every server on this stack, newest first. */
export async function listServers(target: PostgresTarget): Promise<ServerSummary[]> {
  const rows = await queryRows(
    target,
    `SELECT s.id,
            s.name,
            (SELECT count(*) FROM users u WHERE u.server_id = s.id AND NOT u.is_bot),
            (SELECT count(*) FROM channels c WHERE c.server_id = s.id),
            s.created_at
       FROM servers s
      ORDER BY s.created_at DESC`,
  );

  return rows.map((row) => {
    const [id, name, members, channels, createdAt] = row.split(FIELD_SEPARATOR);
    return {
      id,
      name,
      memberCount: Number(members),
      channelCount: Number(channels),
      createdAt,
    };
  });
}

/** An invite that has not been used up, so the dashboard can offer it again. */
export interface ServerInvite {
  serverId: string;
  code: string;
  uses: number;
  maxUses: number;
}

/** Live invites, so a server listed here can be joined without minting one. */
export async function listInvites(target: PostgresTarget): Promise<ServerInvite[]> {
  const rows = await queryRows(
    target,
    `SELECT server_id, code, uses, max_uses
       FROM invites
      WHERE max_uses = 0 OR uses < max_uses
      ORDER BY created_at DESC`,
  );
  return rows.map((row) => {
    const [serverId, code, uses, maxUses] = row.split(FIELD_SEPARATOR);
    return { serverId, code, uses: Number(uses), maxUses: Number(maxUses) };
  });
}

/**
 * The address this stack is handing out right now.
 *
 * Three of the things below — the invite link, the voice URL, and what a new
 * server is told its voice URL is — are the same question asked three times,
 * so they ask it here. [local] is the dashboard's LAN switch: while it is on,
 * the answer is the LAN address rather than the domain.
 */
export function publicUrl(local: LocalTesting | null = null): string {
  if (local) return localPublicUrl(local);
  const domain = setting("RIFT_DOMAIN");
  return setting("API_EXTERNAL_URL") ?? (domain ? `https://${domain}` : "");
}

/** LiveKit's port, when it is published rather than proxied. */
function signallingPort(local: LocalTesting | null): number | undefined {
  if (local) return SIGNALLING_PORT;
  // A stack set up for local testing has always been in this arrangement.
  return setting("RIFT_LOCAL_TESTING") === "true" ? SIGNALLING_PORT : undefined;
}

/**
 * Create a server, using the credentials this stack already holds.
 *
 * The operator supplies a name. Everything `create_server` actually checks —
 * the service key it compares against, the LiveKit URL derived from the
 * domain, and LiveKit's key and secret — is read from the environment the
 * console was set up with.
 */
export async function createServer(
  name: string,
  local: LocalTesting | null = null,
): Promise<{
  serverId: string;
  name: string;
  inviteLink: string;
}> {
  const url = publicUrl(local);
  const serviceKey = setting("SUPABASE_SECRET_KEY") ?? setting("SERVICE_ROLE_KEY");
  const livekitApiKey = setting("LIVEKIT_API_KEY");
  const livekitApiSecret = setting("LIVEKIT_API_SECRET");

  if (!url || !serviceKey || !livekitApiKey || !livekitApiSecret) {
    throw new Error(
      "This stack has not finished setup, so the credentials a server needs " +
        "are not all here yet.",
    );
  }

  const trimmed = name.trim();
  if (trimmed.length === 0) throw new Error("A server needs a name.");

  return await provisionServer({
    publicUrl: url,
    // Whatever arrangement is in force. LiveKit is published directly when
    // nothing is proxying it; a real server shares the domain through Caddy.
    livekitSignallingPort: signallingPort(local),
    // Container-to-container, so creating a server does not wait on DNS or on
    // a certificate that may not have been issued.
    internalUrl: "http://kong:8000",
    serviceRoleKey: serviceKey,
    serverName: trimmed,
    livekitApiKey,
    livekitApiSecret,
  });
}

/**
 * A fresh invite for an existing server.
 *
 * Written straight to the table rather than through an endpoint, because every
 * endpoint that mints one asks the caller to be a member with the right
 * permission — and the console is neither a member nor a caller. It is the
 * operator of the database, which is a different kind of authority and the
 * only one available before anybody has joined.
 */
export async function mintInvite(
  target: PostgresTarget,
  serverId: string,
  maxUses = 1,
): Promise<string> {
  // Both arguments are checked before they are anywhere near a statement.
  // `literal` would keep a bad server id harmless — it doubles the quote, and
  // a SQL injection attempt comes back as an invalid uuid — but a `maxUses` of
  // "abc" became the bare token NaN, which is not injectable and is still a
  // psql syntax error handed to whoever asked.
  if (!/^[0-9a-fA-F-]{36}$/.test(serverId)) {
    throw new Error("That is not a server id.");
  }
  const uses = Number.isInteger(maxUses) ? Math.min(Math.max(maxUses, 1), 1000) : 1;

  const rows = await queryRows(
    target,
    `INSERT INTO invites (server_id, code, role_id, max_uses, uses)
     SELECT s.id, encode(gen_random_bytes(8), 'hex'), r.id, ${uses}, 0
       FROM servers s
       JOIN roles r ON r.server_id = s.id AND r.is_everyone = TRUE
      WHERE s.id = ${literal(serverId)}
     RETURNING code`,
  );
  if (rows.length === 0) throw new Error("No such server on this stack.");
  return rows[0];
}

/** The link an operator pastes into the app. */
export function inviteLinkFor(code: string, local: LocalTesting | null = null): string {
  return `${publicUrl(local).replace(/\/$/, "")}#${code}`;
}

/** The voice URL this stack hands out, for the dashboard to show. */
export function livekitUrl(local: LocalTesting | null = null): string {
  return livekitUrlFor(publicUrl(local), signallingPort(local));
}
