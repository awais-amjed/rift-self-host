import { assert, assertEquals } from "jsr:@std/assert@1";
import {
  composeProblem,
  localLivekitUrl,
  localPublicUrl,
  type LocalTesting,
  problemWithAddress,
  restoreStatements,
} from "./local_testing.ts";
import { inviteLinkFor, livekitUrl, publicUrl } from "./servers.ts";

const local: LocalTesting = { address: "192.168.1.6", port: 18000, restore: {} };

Deno.test("the LAN addresses are the API's port and LiveKit's own", () => {
  assertEquals(localPublicUrl(local), "http://192.168.1.6:18000");
  // Not the API port: nothing is proxying, so signalling is reached directly.
  assertEquals(localLivekitUrl(local), "ws://192.168.1.6:7880");
});

Deno.test("everything a client is handed follows the switch", () => {
  assertEquals(publicUrl(local), "http://192.168.1.6:18000");
  assertEquals(livekitUrl(local), "ws://192.168.1.6:7880");
  assertEquals(inviteLinkFor("abc123", local), "http://192.168.1.6:18000#abc123");
});

/** What a stack with the default ports already has. */
const taken = { 8080: "this console", 443: "the HTTPS port", 7880: "signalling" };

Deno.test("an address is refused before it becomes a URL nothing can reach", () => {
  assertEquals(problemWithAddress("192.168.1.6", 18000, taken), null);
  assert(problemWithAddress("", 18000, taken)?.includes("192.168.1.6"));
  assert(
    problemWithAddress("http://192.168.1.6", 18000, taken)?.includes("without http://"),
  );
  // The port has a box of its own, so an address carrying one would produce
  // `http://192.168.1.6:8000:18000`.
  assert(
    problemWithAddress("192.168.1.6:8000", 18000, taken)?.includes("without a port"),
  );
  assert(problemWithAddress("192.168.1.6", 0, taken)?.includes("between 1 and 65535"));
});

Deno.test("a port this stack already holds is refused, by name", () => {
  // The port an operator reaches for first is the one they are looking at.
  const onConsole = problemWithAddress("192.168.1.6", 8080, taken);
  assert(onConsole?.includes("8080"));
  assert(onConsole?.includes("this console"));
  assert(problemWithAddress("192.168.1.6", 443, taken)?.includes("the HTTPS port"));
  assert(problemWithAddress("192.168.1.6", 7880, taken)?.includes("signalling"));
  // Otherwise Docker refuses a minute later, after the override is written.
  assertEquals(problemWithAddress("192.168.1.6", 8081, taken), null);
});

Deno.test("a compose failure is reported as its reason, not its narration", () => {
  const stderr = [
    " Container rift-db  Running",
    " Container rift-kong  Recreated",
    " Container rift-kong  Starting",
    "Error response from daemon: ports are not available: " +
    "listen tcp4 0.0.0.0:8080: bind: address already in use",
  ].join("\n");
  const problem = composeProblem(stderr);
  assert(problem.startsWith("ports are not available"));
  assert(!problem.includes("rift-db"));
  // Nothing recognisable still beats an empty string.
  assertEquals(composeProblem("something odd\n"), "something odd");
  assertEquals(composeProblem(""), "docker compose failed");
});

Deno.test("switching back restores each server's own URL", () => {
  const a = "11111111-1111-1111-1111-111111111111";
  const b = "22222222-2222-2222-2222-222222222222";
  const statements = restoreStatements(
    { [a]: "wss://one.example.com", [b]: "wss://two.example.com" },
    [a, b],
    "wss://fallback.example.com",
  );
  assertEquals(statements.length, 2);
  assert(statements[0].includes("'wss://one.example.com'"));
  assert(statements[0].includes(`'${a}'`));
  assert(statements[1].includes("'wss://two.example.com'"));
});

Deno.test("a server created while the switch was on lands on the fallback", () => {
  const known = "11111111-1111-1111-1111-111111111111";
  const fresh = "33333333-3333-3333-3333-333333333333";
  const statements = restoreStatements(
    { [known]: "wss://one.example.com" },
    [known, fresh],
    "wss://chat.example.com",
  );
  assertEquals(statements.length, 2);
  assert(statements[1].includes("'wss://chat.example.com'"));
  // Otherwise it is the one server on the stack whose voice never comes back.
  assert(!statements[1].includes("192.168"));
});

Deno.test("a remembered server that has since been deleted is not written back", () => {
  const gone = "44444444-4444-4444-4444-444444444444";
  assertEquals(
    restoreStatements({ [gone]: "wss://one.example.com" }, [], "wss://x").length,
    0,
  );
});
