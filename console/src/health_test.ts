import { assertEquals, assertStringIncludes } from "jsr:@std/assert@1";
import { postsHere, webhooksVerdict } from "./health.ts";
import { webhookBlock } from "./setup/livekit_webhook.ts";

const NAME = "Voice webhooks reach the server";
const template = await Deno.readTextFile(
  new URL("../templates/livekit/livekit.yaml", import.meta.url),
);

Deno.test("the bundled LiveKit posts here as the console writes it", () => {
  assertEquals(postsHere(template.replaceAll(/\{\{[A-Z_]+\}\}/g, "X")), true);
  assertEquals(postsHere(`keys:\n  APIx: secret\n\n${webhookBlock("APIx")}`), true);
});

Deno.test("a livekit.yaml without the block, or posting elsewhere, does not", () => {
  assertEquals(postsHere("keys:\n  APIx: secret\n"), false);
  assertEquals(
    postsHere("webhook:\n  api_key: APIx\n  urls:\n    - https://elsewhere/hook\n"),
    false,
  );
  // Commented out is not there.
  assertEquals(
    postsHere(
      "webhook:\n  api_key: APIx\n  urls:\n#    - http://functions:9000/livekit_webhook\n",
    ),
    false,
  );
  assertEquals(postsHere("webhook: [unclosed"), false);
});

Deno.test("a default node with no calls yet is not a warning", () => {
  const check = webhooksVerdict(NAME, true, [{ isDefault: true, label: "Default" }]);
  assertEquals(check.level, "ok");
});

Deno.test("a region never heard from is named", () => {
  const check = webhooksVerdict(NAME, true, [
    { isDefault: true, label: "Default" },
    { isDefault: false, label: "Singapore" },
  ]);
  assertEquals(check.level, "warn");
  assertStringIncludes(check.detail, "Never heard from: Singapore.");
  assertStringIncludes(check.detail, "MAIN_SERVER");
});

Deno.test("the bundled LiveKit not posting here comes first", () => {
  const check = webhooksVerdict(NAME, false, [{ isDefault: false, label: "Singapore" }]);
  assertEquals(check.level, "warn");
  assertStringIncludes(check.detail, "livekit.yaml");
});

Deno.test("with no bundled file, even a default node never heard from is named", () => {
  const check = webhooksVerdict(NAME, null, [{ isDefault: true, label: "Main" }]);
  assertEquals(check.level, "warn");
  assertStringIncludes(check.detail, "Never heard from: Main.");
});
