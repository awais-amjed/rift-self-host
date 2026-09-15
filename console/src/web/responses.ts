/** The response shapes every route shares. */
import type { Paths } from "../setup/run.ts";

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
 */
export function progressStream(
  work: (send: (value: unknown) => void) => Promise<void>,
): Response {
  const encoder = new TextEncoder();
  const body = new ReadableStream({
    async start(controller) {
      const send = (value: unknown) =>
        controller.enqueue(encoder.encode(JSON.stringify(value) + "\n"));
      try {
        await work(send);
      } catch (error) {
        send({ error: error instanceof Error ? error.message : String(error) });
      } finally {
        controller.close();
      }
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
