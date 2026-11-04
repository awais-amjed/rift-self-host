import { assert, assertEquals, assertStringIncludes } from "jsr:@std/assert@1";
import { placeholders, render } from "./config_files.ts";
import { connectLivekit, webhookBlock, withWebhook } from "./livekit_webhook.ts";
import { defaults } from "./options.ts";
import { generateSecrets } from "./secrets.ts";

const old = "port: 7880\nrtc:\n  udp_port: 7882-7889\nkeys:\n" +
  "  APIkey0001: keysecret\nlogging:\n  level: info\n";

Deno.test("a livekit.yaml from before the webhook gets the block, and keeps the rest", () => {
  const added = withWebhook(old, "APIkey0001");
  assert(added !== null);
  assert(added.startsWith(old), "what was there is left as it was");
  assertStringIncludes(added, webhookBlock("APIkey0001"));
});

Deno.test("a livekit.yaml with a webhook of its own is left alone", () => {
  const own =
    `${old}webhook:\n  api_key: APIkey0001\n  urls:\n    - https://elsewhere/\n`;
  assertEquals(withWebhook(own, "APIkey0001"), null);
});

Deno.test("no webhook for a key livekit.yaml does not hold, which would stop LiveKit", () => {
  // Measured Nov 2 2026: "api_key is required to use webhooks", and no start.
  assertEquals(withWebhook(old, "APIsomethingelse"), null);
});

Deno.test("adding the block twice adds it once", () => {
  const once = withWebhook(old, "APIkey0001")!;
  assertEquals(withWebhook(once, "APIkey0001"), null);
});

Deno.test("a new stack's livekit.yaml carries the same block an old one is given", async () => {
  const ctx = {
    ...defaults,
    domain: "chat.example.com",
    secrets: await generateSecrets(),
  };
  const source = await Deno.readTextFile(
    new URL("../../templates/livekit/livekit.yaml", import.meta.url),
  );
  const rendered = render(source, placeholders(ctx));
  assert(rendered.endsWith(webhookBlock(ctx.secrets.livekitApiKey)));
  assertEquals(withWebhook(rendered, ctx.secrets.livekitApiKey), null);
});

/** A stack for [connectLivekit]: what each step answers, and what was done. */
function stack(opts: { adds: boolean; settled: boolean; restarts: boolean }) {
  const done = { pending: false, restarts: 0 };
  return {
    done,
    steps: {
      addWebhook: () => Promise.resolve(opts.adds),
      pending: () => Promise.resolve(done.pending),
      setPending: (on: boolean) => {
        done.pending = on;
        return Promise.resolve();
      },
      settled: () => Promise.resolve(opts.settled),
      restart: () => {
        done.restarts++;
        return Promise.resolve(opts.restarts);
      },
    },
  };
}

Deno.test("a webhook added while compose is busy is restarted for at the next upgrade", async () => {
  const busy = stack({ adds: true, settled: false, restarts: true });
  assertEquals(await connectLivekit(busy.steps), false);
  assertEquals(busy.done.restarts, 0);
  assert(busy.done.pending, "still owed a restart");

  // The next upgrade finds the block already there, and restarts anyway.
  const next = stack({ adds: false, settled: true, restarts: true });
  next.done.pending = busy.done.pending;
  assertEquals(await connectLivekit(next.steps), true);
  assertEquals(next.done.restarts, 1);
  assert(!next.done.pending, "paid");
});

Deno.test("a failed restart is tried again at the next upgrade", async () => {
  const failing = stack({ adds: true, settled: true, restarts: false });
  assertEquals(await connectLivekit(failing.steps), false);
  assert(failing.done.pending);
});

Deno.test("a stack with its webhook and nothing owed is not restarted", async () => {
  const quiet = stack({ adds: false, settled: true, restarts: true });
  assertEquals(await connectLivekit(quiet.steps), false);
  assertEquals(quiet.done.restarts, 0);
});
