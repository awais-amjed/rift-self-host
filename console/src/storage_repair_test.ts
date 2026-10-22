import { assertEquals, assertThrows } from "jsr:@std/assert@1";
import { FIELD_SEPARATOR } from "./postgres.ts";
import {
  REPAIR_SCRIPT,
  repairObjects,
  STORAGE_ROOT,
  type StoredObject,
  storedObjects,
  type XattrLibrary,
} from "./storage_repair.ts";

Deno.test("an object's file is where storage put it", () => {
  const row = [
    "chat-1",
    "channel/file.bin",
    "v-1",
    "application/octet-stream",
    "no-cache",
  ]
    .join(FIELD_SEPARATOR);
  assertEquals(storedObjects([row]), [{
    path: `${STORAGE_ROOT}/chat-1/channel/file.bin/v-1`,
    contentType: "application/octet-stream",
    cacheControl: "no-cache",
  }]);
});

Deno.test("an object with no recorded metadata gets what an attachment always has", () => {
  const row = ["chat-1", "a.bin", "v-1", "", ""].join(FIELD_SEPARATOR);
  const [object] = storedObjects([row]);
  assertEquals(object.contentType, "application/octet-stream");
  assertEquals(object.cacheControl, "no-cache");
});

Deno.test("the storage root is the one the compose file configures", async () => {
  // Written out rather than read at runtime, because the console cannot see
  // the storage container's environment. A test keeps the two agreeing.
  const compose = await Deno.readTextFile(
    new URL("../../docker-compose.yml", import.meta.url),
  );
  const service = compose.split("\n  storage:\n")[1].split(/\n {2}[a-z][a-z0-9-]*:\n/)[0];
  const environment = (name: string) =>
    service.match(new RegExp(`^\\s+${name}: (.+)$`, "m"))?.[1].trim();

  assertEquals(
    STORAGE_ROOT,
    `${environment("FILE_STORAGE_BACKEND_PATH")}/${environment("TENANT_ID")}/${
      environment("GLOBAL_S3_BUCKET")
    }`,
  );
});

// ── The repair, against stand-ins for storage's xattr library ──────────────

const objects: StoredObject[] = ["bare", "half", "whole", "gone"].map((name) => ({
  path: `${STORAGE_ROOT}/chat-1/${name}/v-1`,
  contentType: "application/octet-stream",
  cacheControl: "no-cache",
}));

/** Files with the attributes they start with; a path not here does not exist. */
function volume() {
  const files = new Map<string, Map<string, string>>([
    [objects[0].path, new Map()],
    [objects[1].path, new Map([["user.supabase.content-type", "image/png"]])],
    [
      objects[2].path,
      new Map([
        ["user.supabase.content-type", "image/png"],
        ["user.supabase.cache-control", "max-age=3600"],
      ]),
    ],
  ]);
  const list = (path: string) => {
    const file = files.get(path);
    if (!file) throw Object.assign(new Error(`ENOENT: ${path}`), { code: "ENOENT" });
    return [...file.keys()];
  };
  const set = (path: string, name: string, value: string) => {
    files.get(path)!.set(name, value);
  };
  return { files, list, set };
}

for (
  const [library, spell] of [
    ["fs-xattr's current names", (v: ReturnType<typeof volume>): XattrLibrary => ({
      listAttributesSync: v.list,
      setAttributeSync: v.set,
    })],
    ["fs-xattr's old names", (v: ReturnType<typeof volume>): XattrLibrary => ({
      listSync: v.list,
      setSync: v.set,
    })],
  ] as const
) {
  Deno.test(`the repair adds only what is missing, with ${library}`, () => {
    const v = volume();
    assertEquals(repairObjects(objects, spell(v)), {
      checked: 4,
      repaired: 2,
      absent: 1,
    });
    assertEquals(Object.fromEntries(v.files.get(objects[0].path)!), {
      "user.supabase.content-type": "application/octet-stream",
      "user.supabase.cache-control": "no-cache",
    });
    // What a file already had is left as it was.
    assertEquals(
      v.files.get(objects[1].path)!.get("user.supabase.content-type"),
      "image/png",
    );
    assertEquals(
      v.files.get(objects[2].path)!.get("user.supabase.cache-control"),
      "max-age=3600",
    );
  });
}

Deno.test("a file the repair cannot read is not reported as missing", () => {
  const library: XattrLibrary = {
    listAttributesSync: () => {
      throw Object.assign(new Error("EACCES: permission denied"), { code: "EACCES" });
    },
    setAttributeSync: () => {},
  };
  assertThrows(() => repairObjects(objects, library), Error, "EACCES");
});

Deno.test("a library with neither spelling stops the repair, saying so", () => {
  assertThrows(() => repairObjects(objects, {}), Error, "no function this repair knows");
});

Deno.test("the script storage runs carries the whole repair", () => {
  // Run as Node would, with nothing of the console in reach: a function that
  // used anything outside itself fails here, not in a restored server.
  const v = volume();
  const out: string[] = [];
  const err: string[] = [];
  const require = (name: string) =>
    name === "fs"
      ? { readFileSync: () => JSON.stringify(objects) }
      : { listAttributesSync: v.list, setAttributeSync: v.set };
  const fakeConsole = {
    log: (line: string) => out.push(line),
    error: (line: string) => err.push(line),
  };
  const fakeProcess = { exit: (code: number) => err.push(`exit ${code}`) };
  new Function("require", "console", "process", REPAIR_SCRIPT)(
    require,
    fakeConsole,
    fakeProcess,
  );
  assertEquals(err, []);
  assertEquals(JSON.parse(out.at(-1)!), { checked: 4, repaired: 2, absent: 1 });
});
