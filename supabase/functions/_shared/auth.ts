import { SupabaseClient } from "@supabase/supabase-js";
import DBSchema from "./schema.ts";
import { CustomResponse } from "./response.ts";
import * as EC from "./error_codes.ts";
import { verifyJwt } from "./jwt.ts";

/**
 * Authenticated caller with server permissions.
 *
 * Identity comes from a verified GoTrue JWT (`auth.uid()`); permissions and ban
 * state come from the **users** profile row (`users.id = auth.uid()`).
 */
export interface AuthenticatedToken {
  /** The caller's id (= auth.uid() = users.id). Kept for API compatibility. */
  tokenId: string;
  serverId: string;
  userId: string;
  isServerAdmin: boolean;
  isChannelManager: boolean;
  canCreateTokens: boolean;
}

/**
 * Verify the caller's GoTrue JWT and load their server permissions.
 * Returns a Response if the JWT is missing/invalid/expired, the caller isn't
 * registered on this server, or they're banned.
 *
 * The ban + permission check hits the DB on every call, so revocation on the
 * edge-function path stays instant even though the JWT itself is stateless
 * (see API.md — short-lived JWTs cover the RLS-only surfaces).
 */
export async function authenticateToken(
  supabase: SupabaseClient,
  token?: string,
): Promise<AuthenticatedToken | Response> {
  if (!token) {
    return CustomResponse.error("Missing required field: token", EC.TOKEN_MISSING);
  }

  // 1. Verify the JWT locally against the stack's JWKS (no GoTrue round-trip).
  //    Ban / deleted-user / permission state is still resolved from the DB below.
  const authUid = await verifyJwt(token);
  if (!authUid) {
    return CustomResponse.error("Invalid or expired token", EC.TOKEN_INVALID);
  }

  // 2. Load this server's profile row. users.id = auth.uid() (see migration 007).
  const { data, error } = await supabase
    .from(DBSchema.users.tableName)
    .select(
      `${DBSchema.users.id}, ${DBSchema.users.serverId}, ${DBSchema.users.isServerAdmin}, ${DBSchema.users.isChannelManager}, ${DBSchema.users.canCreateTokens}, ${DBSchema.users.isBanned}`,
    )
    .eq(DBSchema.users.id, authUid)
    .single();

  if (error || !data) {
    // Authenticated with GoTrue but not registered on this server yet.
    return CustomResponse.error("User not found", EC.USER_NOT_FOUND, error);
  }

  const u = data as Record<string, any>;
  if (u[DBSchema.users.isBanned]) {
    return CustomResponse.error("User is banned", EC.USER_BANNED);
  }

  return {
    tokenId: authUid,
    serverId: u[DBSchema.users.serverId],
    userId: authUid,
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

