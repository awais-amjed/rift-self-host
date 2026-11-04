/**
 * LiveKit's webhook, which tells this server when somebody leaves a call.
 *
 * `livekit_webhook` uses it to remove a watch connection the moment its
 * device's voice connection is gone, rather than at the next roster read
 * (`supabase/functions/_shared/watch.ts`). A server without it still works:
 * the watcher is visible as its owner and is swept later.
 *
 * The block lives in `livekit.yaml` and not in a flag: LiveKit takes the key
 * as `--webhook.api_key` but has no flag for the address, and an address
 * without a key is a LiveKit that does not start. Key and address go in
 * together or not at all.
 */
import { join } from "jsr:@std/path@1";
import { readEnvFile } from "../env_file.ts";
import { secretsFromEnv } from "./config_files.ts";

/**
 * Where the bundled LiveKit posts: the functions container on the stack's own
 * network, never leaving the machine. A region elsewhere posts to the
 * server's public address instead (`/functions/v1/livekit_webhook`).
 */
export const LIVEKIT_WEBHOOK_URL = "http://functions:9000/livekit_webhook";

/** The block for a LiveKit signing with [apiKey]. */
export function webhookBlock(apiKey: string): string {
  return `# Tells this server who leaves its calls (the livekit_webhook endpoint),
# signed with the key above. If you change that key by hand, change it here too.
webhook:
  api_key: ${apiKey}
  urls:
    - ${LIVEKIT_WEBHOOK_URL}
`;
}

/**
 * [yaml] with the webhook block added, or null when it should be left alone:
 * it has a `webhook:` of its own already, or does not list [apiKey] among its
 * keys (edited by hand, and a webhook key LiveKit does not hold stops it).
 */
export function withWebhook(yaml: string, apiKey: string): string | null {
  if (/^webhook:/m.test(yaml)) return null;
  const listed = yaml.split("\n").some((line) =>
    line.trimStart().startsWith(`${apiKey}:`)
  );
  if (!listed) return null;
  return `${yaml.replace(/\n*$/, "\n")}\n${webhookBlock(apiKey)}`;
}

/**
 * Add the block to a stack's `livekit.yaml` if it has none, answering whether
 * it did: LiveKit reads the file only as it starts, so the caller restarts it.
 */
export async function ensureLivekitWebhook(projectDir: string): Promise<boolean> {
  const path = join(projectDir, "volumes/livekit/livekit.yaml");
  let yaml: string;
  try {
    yaml = await Deno.readTextFile(path);
  } catch {
    return false;
  }
  const apiKey = secretsFromEnv(readEnvFile(projectDir)).livekitApiKey;
  if (!apiKey) return false;
  const wanted = withWebhook(yaml, apiKey);
  if (wanted === null) return false;
  await Deno.writeTextFile(path, wanted);
  return true;
}

/** What [connectLivekit] needs of the stack, so it can be tested without one. */
export interface LivekitSteps {
  /** [ensureLivekitWebhook]: true when it wrote the block. */
  addWebhook: () => Promise<boolean>;
  /** Whether a block was written and LiveKit not yet restarted to read it. */
  pending: () => Promise<boolean>;
  setPending: (on: boolean) => Promise<void>;
  /** Compose is not still working on this project. */
  settled: () => Promise<boolean>;
  /** Restart LiveKit, answering whether it did. */
  restart: () => Promise<boolean>;
}

/**
 * Add the webhook if the stack has none, and restart LiveKit to read it,
 * answering whether it was restarted.
 *
 * The restart is owed until it happens, not only on the upgrade that wrote
 * the block: when compose was busy or the restart failed, every later upgrade
 * found the block already there and did nothing, and LiveKit sent no events
 * until something else restarted it.
 */
export async function connectLivekit(steps: LivekitSteps): Promise<boolean> {
  if (await steps.addWebhook()) await steps.setPending(true);
  if (!await steps.pending()) return false;
  if (!await steps.settled()) return false;
  if (!await steps.restart()) return false;
  await steps.setPending(false);
  return true;
}
