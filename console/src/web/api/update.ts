/** The Overview tab's Update: what is available, and moving to it. */
import { runUpdate, updateRunning, updateStatus } from "../../update/run.ts";
import { type ApiRoutes, json, progressStream } from "../responses.ts";

export const updateRoutes: ApiRoutes = async (request, url) => {
  const path = url.pathname;

  if (path === "/api/update" && request.method === "GET") {
    return json(await updateStatus());
  }

  if (path === "/api/update" && request.method === "POST") {
    if (updateRunning()) {
      return json({ error: "An update is already running." }, 409);
    }
    // The version the page showed, so what is installed is the release whose
    // notes were read, not one published since the page loaded.
    const { version, keepCompose } = await request.json().catch(() => ({}));
    return progressStream(async (send) => {
      const outcome = await runUpdate(
        {
          version: typeof version === "string" ? version : undefined,
          keepCompose: keepCompose === true,
        },
        (progress) => {
          if (!progress.done) console.log(`[update] ${progress.step}`);
          send(progress);
        },
      );
      console.log(`[update] ${outcome.kind} ${outcome.version}`);
      send({ outcome });
    });
  }

  return null;
};
