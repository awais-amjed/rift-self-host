import { assertEquals } from "jsr:@std/assert@1";
import { FIELD_SEPARATOR } from "./postgres.ts";
import { STORAGE_ROOT, storedObjects } from "./storage_repair.ts";

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
