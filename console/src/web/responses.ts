/** The response shapes every route shares. */
import type { Paths } from "../setup/run.ts";
import { acquire, OperationBusy } from "../operation.ts";

/**
 * One area's endpoints: a response when the request is one of its paths,
 * null to let the next area look.
 */
export type ApiRoutes = (
  request: Request,
  url: URL,
  paths: Paths,
) => Promise<Response | null>;

export function html(body: string, headers: HeadersInit = {}): Response {
  return new Response(body, {
    headers: { "Content-Type": "text/html; charset=utf-8", ...headers },
  });
}

export function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

/**
 * A failure the operator can read, without the query that caused it.
 *
 * psql answers with the statement, its line number and a caret — useful in a
 * terminal, and a description of the schema on a web page. The full text goes
 * to the container log, where the person who can already read the database is
 * the only one who sees it.
 */
export function failure(context: string, error: unknown): Response {
  console.error(`[${context}]`, error);
  const message = error instanceof Error ? error.message : String(error);
  const clean = message.startsWith("psql:")
    ? "The database refused that. See `docker compose logs console` for the reason."
    : message;
  return json({ error: clean }, 400);
}

/**
 * Take the console's one lock for [name] ([acquire]), or the 409 that says what
 * holds it. The caller releases it when its work ends.
 */
export function holdOrRefuse(projectDir: string, name: string): (() => void) | Response {
  try {
    return acquire(projectDir, name);
  } catch (error) {
    if (error instanceof OperationBusy) return json({ error: error.message }, 409);
    throw error;
  }
}

/** [work] under the lock for [name]; a 409 when something else holds it. */
export async function exclusiveResponse<T extends Response | null>(
  projectDir: string,
  name: string,
  work: () => Promise<T>,
): Promise<T | Response> {
  const release = holdOrRefuse(projectDir, name);
  if (release instanceof Response) return release;
  try {
    return await work();
  } finally {
    release();
  }
}

export function redirect(to: string, headers: HeadersInit = {}): Response {
  return new Response(null, { status: 303, headers: { Location: to, ...headers } });
}

/**
 * Run [work], streaming one JSON object per line as it calls `send`.
 *
 * Newline-delimited JSON rather than server-sent events: the page needs no
 * reconnection and no event types, and a plain stream is one `getReader()`
 * loop on the other end. Setup and restore both pull images, which can take
 * minutes, and a request that returns nothing for that long reads as a hang.
 * An error thrown by [work] becomes the stream's last line.
 *
 * The work does not depend on anybody reading. A page closed, reloaded or cut
 * off with its SSH tunnel cancels the stream, after which every `enqueue`
 * throws, and that throw used to surface inside the work through its progress
 * callback: a restore stopped between loading the database and putting the
 * attachments back. Now a send to a closed page is dropped, and the work runs
 * to its end, reported in the log and in the console's state as before.
 */
export function progressStream(
  work: (send: (value: unknown) => void) => Promise<void>,
): Response {
  const encoder = new TextEncoder();
  let open = true;
  const body = new ReadableStream({
    start(controller) {
      const send = (value: unknown) => {
        if (!open) return;
        try {
          controller.enqueue(encoder.encode(JSON.stringify(value) + "\n"));
        } catch {
          open = false;
        }
      };
      // Not awaited: `start` holding the stream until the work ends is what
      // tied the two together.
      void (async () => {
        try {
          await work(send);
        } catch (error) {
          send({ error: error instanceof Error ? error.message : String(error) });
        } finally {
          if (open) {
            try {
              controller.close();
            } catch {
              // Cancelled meanwhile.
            }
          }
        }
      })();
    },
    cancel() {
      open = false;
    },
  });
  return new Response(body, {
    headers: {
      "Content-Type": "application/x-ndjson",
      "Cache-Control": "no-store",
      // Nothing buffers this today, but a reverse proxy in front of the console
      // would, and the stream is the only feedback while it runs.
      "X-Accel-Buffering": "no",
    },
  });
}
