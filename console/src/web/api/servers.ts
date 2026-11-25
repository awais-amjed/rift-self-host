/**
 * The Servers tab's endpoints: the list, creating one, invite links, and the
 * largest file the machine accepts.
 */
import {
  createServer,
  inviteLinkFor,
  listInvites,
  listServers,
  mintInvite,
} from "../../servers.ts";
import { readLocalTesting } from "../../local_testing.ts";
import { changeFileCeiling, readFileCeiling } from "../../file_ceiling.ts";
import { targetFromEnv } from "../../postgres.ts";
import { type ApiRoutes, exclusiveResponse, failure, json } from "../responses.ts";

export const serverRoutes: ApiRoutes = async (request, url, paths) => {
  const path = url.pathname;

  if (path === "/api/files") {
    if (request.method === "POST") {
      const { mb } = await request.json();
      const changed = await exclusiveResponse(
        paths.projectDir,
        "changing the file limit",
        async () => {
          try {
            await changeFileCeiling(targetFromEnv(), paths.projectDir, Number(mb));
            return null;
          } catch (error) {
            return json(
              { error: error instanceof Error ? error.message : String(error) },
              400,
            );
          }
        },
      );
      if (changed !== null) return changed;
    }
    return json(await readFileCeiling(paths.projectDir));
  }

  if (path === "/api/servers") {
    const target = targetFromEnv();
    let servers;
    try {
      servers = await listServers(target);
    } catch (error) {
      // Not "No servers yet": a database that did not answer is not an empty one.
      return failure("servers", error);
    }
    const [invites, local] = await Promise.all([
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
      return failure("servers/invite", error);
    }
  }

  return null;
};
