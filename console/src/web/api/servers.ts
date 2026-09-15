/** The Servers tab's endpoints: the list, creating one, and invite links. */
import {
  createServer,
  inviteLinkFor,
  listInvites,
  listServers,
  mintInvite,
} from "../../servers.ts";
import { readLocalTesting } from "../../local_testing.ts";
import { targetFromEnv } from "../../postgres.ts";
import { type ApiRoutes, failure, json } from "../responses.ts";

export const serverRoutes: ApiRoutes = async (request, url) => {
  const path = url.pathname;

  if (path === "/api/servers") {
    const target = targetFromEnv();
    const [servers, invites, local] = await Promise.all([
      listServers(target).catch(() => []),
      listInvites(target).catch(() => []),
      readLocalTesting(target).catch(() => null),
    ]);
    return json({
      servers,
      // One live invite per server is all the dashboard offers: a list of every
      // outstanding code would be a list of ways into the server, on a page.
      invites: servers.map((server) => {
        const invite = invites.find((i) => i.serverId === server.id);
        return invite
          ? { serverId: server.id, link: inviteLinkFor(invite.code, local) }
          : null;
      }).filter((entry) => entry !== null),
    });
  }

  if (path === "/api/servers/create" && request.method === "POST") {
    const { name } = await request.json();
    try {
      const created = await createServer(
        String(name ?? ""),
        await readLocalTesting(targetFromEnv()).catch(() => null),
      );
      return json(created);
    } catch (error) {
      return failure("servers/create", error);
    }
  }

  if (path === "/api/servers/invite" && request.method === "POST") {
    const { serverId, maxUses } = await request.json();
    const target = targetFromEnv();
    try {
      const code = await mintInvite(target, String(serverId), Number(maxUses ?? 1));
      const local = await readLocalTesting(target).catch(() => null);
      return json({ link: inviteLinkFor(code, local) });
    } catch (error) {
      return json({ error: error instanceof Error ? error.message : String(error) }, 400);
    }
  }

  return null;
};
