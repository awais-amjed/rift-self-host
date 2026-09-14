/**
 * Putting back the file metadata a restored attachment lost.
 *
 * Storage's file backend keeps each object's content type and cache control in
 * extended attributes on the file itself, not in the database — and the image
 * this stack pins throws "The extended attribute does not exist" when one is
 * missing, rather than falling back. Most ways of copying files drop them,
 * including busybox `tar`, which the backup instructions used. A restored
 * server had every message and every attachment's bytes intact, and every
 * attachment answered 500. Found by restoring a real backup and opening one in
 * the app.
 *
 * The database still records both values for every object, so nothing is
 * actually lost; they only need writing back. That happens inside the storage
 * container, with the xattr library storage itself uses, because it is the one
 * process that can see the volume.
 */
import { FIELD_SEPARATOR, type PostgresTarget, queryRows } from "./postgres.ts";
import { execInService } from "./docker.ts";

/**
 * Where storage keeps objects: `FILE_STORAGE_BACKEND_PATH`, then `TENANT_ID`,
 * then `GLOBAL_S3_BUCKET`, from the storage service in docker-compose.yml. A
 * test holds this to that file.
 */
export const STORAGE_ROOT = "/var/lib/storage/stub/stub";

/** One object's file, and the two attributes storage expects on it. */
export interface StoredObject {
  path: string;
  contentType: string;
  cacheControl: string;
}

/** What storage would do with a gap: an attachment is ciphertext, never cached. */
const DEFAULT_CONTENT_TYPE = "application/octet-stream";
const DEFAULT_CACHE_CONTROL = "no-cache";

/** `storage.objects` rows — bucket, name, version, mimetype, cache control — as files. */
export function storedObjects(rows: string[]): StoredObject[] {
  return rows.map((row) => {
    const [bucket, name, version, contentType, cacheControl] = row.split(FIELD_SEPARATOR);
    return {
      path: `${STORAGE_ROOT}/${bucket}/${name}/${version}`,
      contentType: contentType || DEFAULT_CONTENT_TYPE,
      cacheControl: cacheControl || DEFAULT_CACHE_CONTROL,
    };
  });
}

/**
 * Runs in storage's own Node, from its working directory where `fs-xattr` is
 * installed. Reads the objects as JSON on stdin; only adds an attribute that is
 * missing, so a healthy volume is left exactly as it was.
 */
const REPAIR_SCRIPT = `
const fs = require("fs");
const xattr = require("fs-xattr");
const objects = JSON.parse(fs.readFileSync(0, "utf8"));
let repaired = 0;
let absent = 0;
for (const object of objects) {
  let names;
  try {
    names = xattr.listSync(object.path);
  } catch {
    absent++;
    continue;
  }
  let touched = false;
  if (!names.includes("user.supabase.content-type")) {
    xattr.setSync(object.path, "user.supabase.content-type", object.contentType);
    touched = true;
  }
  if (!names.includes("user.supabase.cache-control")) {
    xattr.setSync(object.path, "user.supabase.cache-control", object.cacheControl);
    touched = true;
  }
  if (touched) repaired++;
}
console.log(JSON.stringify({ checked: objects.length, repaired, absent }));
`;

/** What a repair found. */
export interface RepairReport {
  checked: number;
  repaired: number;
  /** In the database and not on disk — an attachments backup that was not restored. */
  absent: number;
}

/** Write back any missing attachment metadata. Quiet when there is none to write. */
export async function repairAttachmentMetadata(
  target: PostgresTarget,
): Promise<RepairReport> {
  const rows = await queryRows(
    target,
    `SELECT bucket_id, name, version, metadata->>'mimetype', metadata->>'cacheControl'
       FROM storage.objects
      WHERE version IS NOT NULL`,
  );
  const objects = storedObjects(rows);
  if (objects.length === 0) return { checked: 0, repaired: 0, absent: 0 };

  const result = await execInService(
    "storage",
    ["node", "-e", REPAIR_SCRIPT],
    JSON.stringify(objects),
  );
  if (!result.ok) {
    throw new Error(
      result.stderr.split("\n").at(-1) || "storage exited without saying why",
    );
  }
  return JSON.parse(result.stdout.split("\n").at(-1) ?? "{}") as RepairReport;
}
