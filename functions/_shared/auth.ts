import { SupabaseClient } from "@supabase/supabase-js";
import DBSchema from "./schema.ts";
import { CustomResponse } from "./response.ts";
import * as EC from "./error_codes.ts";

/**
 * Authenticated token record with user permissions.
 *
 * Permissions are sourced from the **users** table.
 * Tokens are always linked to a user (invites are a separate table).
 */
export interface AuthenticatedToken {
  tokenId: string;
  serverId: string;
  userId: string;
  isServerAdmin: boolean;
  isChannelManager: boolean;
  canCreateTokens: boolean;
}

/**
 * Validate an access token and return the token record with user permissions.
 * Returns a Response if the token is missing, invalid, or not linked to a user.
 *
 * Uses a single JOIN query (tokens → users via FK) instead of two sequential
 * round-trips, cutting auth overhead by ~50% on every protected endpoint.
 */
export async function authenticateToken(
  supabase: SupabaseClient,
  token?: string,
): Promise<AuthenticatedToken | Response> {
  if (!token) {
    return CustomResponse.error("Missing required field: token", EC.TOKEN_MISSING);
  }

  // One round-trip: fetch token + user permissions via the FK relationship.
  // PostgREST embeds the related users row as a nested object under the table name.
  const { data, error } = await supabase
    .from(DBSchema.tokens.tableName)
    .select(
      `${DBSchema.tokens.id},` +
      ` ${DBSchema.tokens.serverId},` +
      ` ${DBSchema.tokens.userId},` +
      ` ${DBSchema.tokens.expiresAt},` +
      ` ${DBSchema.users.tableName}(${DBSchema.users.isServerAdmin}, ${DBSchema.users.isChannelManager}, ${DBSchema.users.canCreateTokens}, ${DBSchema.users.isBanned})`,
    )
    .eq(DBSchema.tokens.token, token)
    .single();

  if (error || !data) {
    console.log(`[auth] Token lookup failed for token="${token?.substring(0,8)}...": ${JSON.stringify(error)}`);
    return CustomResponse.error("Invalid token provided", EC.TOKEN_INVALID, error);
  }

  const d = data as Record<string, any>;

  // Reject expired tokens
  const expiresAt = new Date(d[DBSchema.tokens.expiresAt]);
  if (expiresAt < new Date()) {
    return CustomResponse.error("Token has expired — please re-authenticate", EC.TOKEN_EXPIRED);
  }

  const userId = d[DBSchema.tokens.userId];
  if (!userId) {
    return CustomResponse.error("Token is not linked to a user", EC.TOKEN_UNLINKED);
  }

  // The embedded users row — null if the user was deleted (ON DELETE SET NULL)
  const u = d[DBSchema.users.tableName] as Record<string, any> | null;
  if (!u) {
    return CustomResponse.error("User not found", EC.USER_NOT_FOUND);
  }

  if (u[DBSchema.users.isBanned]) {
    return CustomResponse.error("User is banned", EC.USER_BANNED);
  }

  return {
    tokenId: d[DBSchema.tokens.id],
    serverId: d[DBSchema.tokens.serverId],
    userId,
    isServerAdmin: u[DBSchema.users.isServerAdmin],
    isChannelManager: u[DBSchema.users.isChannelManager],
    canCreateTokens: u[DBSchema.users.canCreateTokens],
  };
}

/**
 * Type guard: checks if the authenticateToken result is an error Response.
 */
export function isAuthError(
  result: AuthenticatedToken | Response,
): result is Response {
  return result instanceof Response;
}

/**
 * Extracts the Bearer token from the Authorization header of a request.
 * Returns undefined if the header is missing or not in "Bearer <token>" format.
 */
export function extractBearerToken(req: Request): string | undefined {
  const authHeader = req.headers.get("Authorization") ?? "";
  if (!authHeader.startsWith("Bearer ")) return undefined;
  const token = authHeader.slice(7).trim();
  return token.length > 0 ? token : undefined;
}

