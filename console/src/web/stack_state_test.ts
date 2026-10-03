import { assertEquals } from "jsr:@std/assert@1";
import { isConfigured, setupUnfinished } from "./stack_state.ts";

/** Run [check] against a project directory whose `.env` holds [lines]. */
async function withEnv(lines: string[], check: () => void): Promise<void> {
  const dir = await Deno.makeTempDir();
  const before = Deno.env.get("RIFT_PROJECT_DIR");
  try {
    await Deno.writeTextFile(`${dir}/.env`, lines.join("\n") + "\n");
    Deno.env.set("RIFT_PROJECT_DIR", dir);
    check();
  } finally {
    if (before === undefined) Deno.env.delete("RIFT_PROJECT_DIR");
    else Deno.env.set("RIFT_PROJECT_DIR", before);
    await Deno.remove(dir, { recursive: true });
  }
}

Deno.test("a setup still running is not a configured stack", async () => {
  // Setup writes its secrets in the first step. Counting that as configured
  // showed a login page, mid-setup, for a password nobody had seen yet.
  await withEnv(["JWT_SECRET=x", "RIFT_SETUP=running"], () => {
    assertEquals(setupUnfinished(), true);
    assertEquals(isConfigured(), false);
  });
});

Deno.test("a finished setup is configured", async () => {
  await withEnv(["JWT_SECRET=x", "RIFT_SETUP=done"], () => {
    assertEquals(setupUnfinished(), false);
    assertEquals(isConfigured(), true);
  });
});

Deno.test("a stack set up before the marker existed still counts as set up", async () => {
  await withEnv(["JWT_SECRET=x"], () => assertEquals(isConfigured(), true));
});

Deno.test("a hand-written .env without secrets is not set up", async () => {
  await withEnv(
    ["RIFT_DOMAIN=chat.example.com"],
    () => assertEquals(isConfigured(), false),
  );
});
