import { assertEquals, assertStringIncludes } from "jsr:@std/assert@1";
import { requestProblem } from "./routes.ts";

function post(path: string, headers: Record<string, string>): Request {
  return new Request(`http://localhost:8080${path}`, { method: "POST", headers });
}

Deno.test("another site's page cannot post to the console", () => {
  const json = { "content-type": "application/json", host: "localhost:8080" };
  assertEquals(requestProblem(post("/api/setup", json), false), null);
  assertEquals(
    requestProblem(
      post("/api/setup", { ...json, origin: "http://localhost:8080" }),
      false,
    ),
    null,
  );
  assertStringIncludes(
    requestProblem(
      post("/api/setup", { ...json, origin: "https://evil.example" }),
      false,
    )!,
    "another site",
  );
  assertStringIncludes(
    requestProblem(
      post("/api/setup", { ...json, "sec-fetch-site": "cross-site" }),
      true,
    )!,
    "another site",
  );
  // A text/plain body needs no preflight, so it is what a hostile page sends.
  assertStringIncludes(
    requestProblem(
      post("/api/setup", { "content-type": "text/plain", host: "localhost:8080" }),
      false,
    )!,
    "JSON",
  );
});

Deno.test("before a password only a loopback name is answered", () => {
  const rebound = new Request("http://attacker.example:8080/", {
    headers: { host: "attacker.example:8080" },
  });
  assertStringIncludes(requestProblem(rebound, false)!, "localhost");
  // With one, the console can be reached by any name its operator gives it.
  assertEquals(requestProblem(rebound, true), null);
  for (const host of ["localhost:8080", "127.0.0.1:8080", "[::1]:8080"]) {
    const request = new Request(`http://${host}/`, { headers: { host } });
    assertEquals(requestProblem(request, false), null, host);
  }
});

Deno.test("sign-in is a form, and is not held to JSON", () => {
  const form = post("/login", {
    "content-type": "application/x-www-form-urlencoded",
    host: "localhost:8080",
    origin: "http://localhost:8080",
  });
  assertEquals(requestProblem(form, true), null);
});
