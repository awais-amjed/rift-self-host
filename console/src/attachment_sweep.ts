import { setting } from "./env_file.ts";

/**
 * The attachment sweep, run from here on a timer.
 *
 * Only something holding the service key can remove a file from storage, so
 * the sweep is an edge function, `sweep_attachments`. Until self-host 064
 * every app asked it each time it opened a server, which was one function
 * call per member per server shown, nearly all of them answering "not due
 * yet". The console asks instead, every few minutes, and an app that hears
 * `server_start` say `sweeps_itself` stops asking. A server nobody opens is
 * swept now too.
 *
 * The database still decides what goes and how often (`claim_attachment_sweep`,
 * once a minute), so an older app asking as well removes nothing twice.
 */

const EVERY_MS = 5 * 60 * 1000;
const FIRST_MS = 2 * 60 * 1000;

/** How many full batches one round removes before waiting for the next. */
const MOST_PASSES = 10;

/** Ask the stack to sweep, as many passes as come back full. */
export async function sweepAttachmentsNow(
  internalUrl = "http://kong:8000",
): Promise<{ swept: number }> {
  const serviceKey = setting("SUPABASE_SECRET_KEY") ?? setting("SERVICE_ROLE_KEY");
  if (!serviceKey) return { swept: 0 };
  const endpoint = `${internalUrl.replace(/\/$/, "")}/functions/v1/sweep_attachments`;
  let swept = 0;
  for (let pass = 0; pass < MOST_PASSES; pass++) {
    const response = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ service_key: serviceKey }),
      signal: AbortSignal.timeout(60_000),
    });
    const body = await response.json().catch(() => null) as
      | { success?: boolean; data?: { swept?: number; more?: boolean }; error?: string }
      | null;
    if (body?.success !== true) {
      throw new Error(body?.error ?? `the sweep answered ${response.status}`);
    }
    swept += body.data?.swept ?? 0;
    // `claim_attachment_sweep` lets one pass a minute through, so a full
    // batch's next pass waits for the next round rather than being refused.
    if (body.data?.more !== true) break;
    await new Promise((resolve) => setTimeout(resolve, 61_000));
  }
  return { swept };
}

/** Sweep a couple of minutes after start, then every five, while [isReady]. */
export function startAttachmentSweep(isReady: () => boolean): void {
  let running = false;
  const round = async () => {
    if (running || !isReady()) return;
    running = true;
    try {
      const { swept } = await sweepAttachmentsNow();
      if (swept > 0) console.log(`[sweep] removed ${swept} attachment files nobody holds`);
    } catch (error) {
      console.error("[sweep] attachments:", error instanceof Error ? error.message : error);
    } finally {
      running = false;
    }
  };
  setTimeout(() => {
    void round();
    setInterval(() => void round(), EVERY_MS);
  }, FIRST_MS);
}
