import { assert, assertEquals } from "jsr:@std/assert@1";
import {
  compareVersions,
  needsCheck,
  newerReleases,
  type Release,
  releasesFrom,
} from "./releases.ts";

Deno.test("versions sort the way semver does", () => {
  const sorted = [
    "1.0.10",
    "1.1.0",
    "1.0.9",
    "1.1.0-beta.10",
    "1.1.0-beta.2",
    "1.1.0-alpha.1",
    "2.0.0",
  ].sort(compareVersions);
  assertEquals(sorted, [
    "1.0.9",
    "1.0.10",
    "1.1.0-alpha.1",
    "1.1.0-beta.2",
    "1.1.0-beta.10",
    "1.1.0",
    "2.0.0",
  ]);
  assertEquals(compareVersions("1.0.12", "1.0.12"), 0);
  // Something that is not a version is never newer than one.
  assert(compareVersions("unknown", "1.0.0") < 0);
});

const release = (version: string, prerelease = false): Release => ({
  version,
  notes: "",
  url: "",
  prerelease,
});

Deno.test("only releases after this one are offered, newest first", () => {
  const all = [
    release("1.0.11"),
    release("1.0.14"),
    release("1.0.12"),
    release("1.0.13"),
  ];
  assertEquals(newerReleases(all, "1.0.12").map((r) => r.version), ["1.0.14", "1.0.13"]);
  assertEquals(newerReleases(all, "1.0.14"), []);
});

Deno.test("a pre-release is offered only to a console running one", () => {
  const all = [release("1.0.13"), release("1.1.0-beta.1", true)];
  assertEquals(newerReleases(all, "1.0.12").map((r) => r.version), ["1.0.13"]);
  assertEquals(
    newerReleases([...all, release("1.1.0-beta.2", true)], "1.1.0-beta.1")
      .map((r) => r.version),
    ["1.1.0-beta.2"],
  );
});

Deno.test("GitHub's list is read without its drafts or stray tags", () => {
  const releases = releasesFrom([
    { tag_name: "v1.0.13", body: " notes \n", html_url: "u", prerelease: false },
    { tag_name: "v1.0.14", body: "x", draft: true },
    { tag_name: "nightly", body: "x" },
    { tag_name: "v1.1.0-beta.1", prerelease: true },
  ]);
  assertEquals(releases, [
    { version: "1.0.13", notes: "notes", url: "u", prerelease: false },
    { version: "1.1.0-beta.1", notes: "", url: "", prerelease: true },
  ]);
  assertEquals(releasesFrom({ message: "rate limited" }), []);
});

Deno.test("GitHub is asked hourly, after a failure in five minutes, on Check now in one", () => {
  const minute = 60_000;
  const answer = { at: 0, releases: [] };
  const failure = { at: 0, releases: null };
  assert(needsCheck(null, 0, false));
  assert(!needsCheck(answer, 59 * minute, false));
  assert(needsCheck(answer, 61 * minute, false));
  assert(!needsCheck(failure, 4 * minute, false));
  assert(needsCheck(failure, 6 * minute, false));
  // Pressing Check now over and over still asks at most once a minute.
  assert(!needsCheck(answer, 30_000, true));
  assert(needsCheck(answer, 2 * minute, true));
  assert(needsCheck(failure, 2 * minute, true));
});
