import { assertEquals, assertRejects, assertStringIncludes } from "jsr:@std/assert@1";
import { livekitUrlFor, type ProvisionOptions, provisionServer } from "./provision.ts";

const options: ProvisionOptions = {
  publicUrl: "https://chat.example.com",
  internalUrl: "http://kong:8000",
  serviceRoleKey: "service-role-key",
  serverName: "Example",
  livekitApiKey: "APIabc",
  livekitApiSecret: "shh",
};

/** Answer the next fetch with [body], and record what was sent. */
function stubFetch(body: unknown, status = 200) {
  const calls: { url: string; body: Record<string, unknown> }[] = [];
  const original = globalThis.fetch;
  globalThis.fetch = (input: string | URL | Request, init?: RequestInit) => {
    calls.push({
      url: String(input),
      body: JSON.parse(String(init?.body ?? "{}")),
    });
    return Promise.resolve(
      new Response(typeof body === "string" ? body : JSON.stringify(body), { status }),
    );
  };
  return { calls, restore: () => (globalThis.fetch = original) };
}

Deno.test("voice shares the domain, over wss", () => {
  // The Caddyfile routes LiveKit's paths on the same host, so this is derived
  // rather than configured — a second value would be a second thing to get
  // out of step with the first.
  assertEquals(livekitUrlFor("https://chat.example.com"), "wss://chat.example.com");
  assertEquals(livekitUrlFor("https://chat.example.com/"), "wss://chat.example.com");
});

Deno.test("the operator gets a link, never the service key", async () => {
  const stub = stubFetch({
    success: true,
    data: { server_id: "srv-1", name: "Example", invite_code: "abc123" },
  });

  try {
    const server = await provisionServer(options);
    assertEquals(server.inviteLink, "https://chat.example.com#abc123");
    assertEquals(server.serverId, "srv-1");

    // The call goes container-to-container, so setup does not wait on DNS
    // propagation or on a certificate that has not been issued yet.
    assertEquals(stub.calls[0].url, "http://kong:8000/functions/v1/create_server");
    assertEquals(stub.calls[0].body.livekit_url, "wss://chat.example.com");
  } finally {
    stub.restore();
  }
});

Deno.test("a refusal is not read as a server", async () => {
  // The edge functions answer errors with HTTP 200 by convention. Checking
  // response.ok would take this for success and hand back an invite link to a
  // server that was never created.
  const stub = stubFetch({ success: false, error: "Invalid service role key" }, 200);

  try {
    const error = await assertRejects(() => provisionServer(options));
    assertStringIncludes(String(error), "Invalid service role key");
  } finally {
    stub.restore();
  }
});

Deno.test("an HTML error page is reported as itself", async () => {
  // A misrouted request reaches Kong's error page, not the function. Without
  // this the operator sees a JSON parse error about an unexpected '<'.
  const stub = stubFetch("<html>502 Bad Gateway</html>", 502);

  try {
    const error = await assertRejects(() => provisionServer(options));
    assertStringIncludes(String(error), "not JSON");
    assertStringIncludes(String(error), "502");
  } finally {
    stub.restore();
  }
});
