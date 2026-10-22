/**
 * Encrypting a backup with a passphrase, as a stream.
 *
 * A backup holds `.env`, which is every key the server has, so an optional
 * passphrase turns the file from "the server" into "the server, for whoever
 * knows this". The file can be gigabytes of attachments and WebCrypto only
 * encrypts whole buffers, so the plaintext is sealed in fixed-size chunks:
 * AES-256-GCM each, with the chunk's position in its nonce so chunks cannot be
 * reordered, and a flag on the last one so the file cannot be quietly cut
 * short. The key comes from the passphrase through PBKDF2-SHA-256.
 *
 * Each attachment in a backup is sealed on its own, so that the next backup
 * can share the file instead of copying it. PBKDF2 is deliberately slow, so a
 * backup derives one key ([deriveSealKey]) and seals every attachment with
 * it; each file still carries the salt in its header and opens with the
 * passphrase alone.
 *
 * Layout: MAGIC, salt (16), iterations (u32), chunk size (u32), nonce prefix
 * (8); then frames of [u32 ciphertext length][ciphertext with its 16-byte tag].
 */

const MAGIC = new TextEncoder().encode("RIFTSEAL1");
const SALT_BYTES = 16;
const PREFIX_BYTES = 8;
const TAG_BYTES = 16;
const HEADER_BYTES = MAGIC.length + SALT_BYTES + 4 + 4 + PREFIX_BYTES;

/** OWASP's floor for PBKDF2-SHA-256. A backup is opened rarely; slow is fine. */
export const DEFAULT_ITERATIONS = 600_000;
export const DEFAULT_CHUNK_BYTES = 1024 * 1024;

/** Refused on open, so a crafted header cannot ask for a year of PBKDF2. */
const MAX_ITERATIONS = 10_000_000;
const MAX_CHUNK_BYTES = 64 * 1024 * 1024;

const MIDDLE = new Uint8Array([0]);
const FINAL = new Uint8Array([1]);

/** Anything wrong with a sealed backup, in a sentence for the person restoring it. */
export class SealError extends Error {}

/** Tuning, for tests: the defaults are right for real backups. */
export interface SealOptions {
  iterations?: number;
  chunkBytes?: number;
}

/** A key derived once, to seal many files with one passphrase. */
export interface SealKey {
  key: CryptoKey;
  salt: Uint8Array<ArrayBuffer>;
  iterations: number;
  chunkBytes: number;
}

export async function deriveSealKey(
  passphrase: string,
  options: SealOptions = {},
): Promise<SealKey> {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const iterations = options.iterations ?? DEFAULT_ITERATIONS;
  return {
    key: await deriveKey(passphrase, salt, iterations),
    salt,
    iterations,
    chunkBytes: options.chunkBytes ?? DEFAULT_CHUNK_BYTES,
  };
}

async function deriveKey(
  passphrase: string,
  salt: Uint8Array<ArrayBuffer>,
  iterations: number,
): Promise<CryptoKey> {
  const material = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(passphrase),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  return await crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

function nonceFor(prefix: Uint8Array, index: number): Uint8Array<ArrayBuffer> {
  const nonce = new Uint8Array(12);
  nonce.set(prefix, 0);
  new DataView(nonce.buffer).setUint32(8, index);
  return nonce;
}

/** Whether a file starting with [head] is sealed: its first bytes are the magic. */
export function looksSealed(head: Uint8Array): boolean {
  return head.length >= MAGIC.length && startsLikeMagic(head);
}

/** Whether [bytes] agree with the magic for as far as both go. */
function startsLikeMagic(bytes: Uint8Array): boolean {
  const length = Math.min(bytes.length, MAGIC.length);
  for (let i = 0; i < length; i++) {
    if (bytes[i] !== MAGIC[i]) return false;
  }
  return true;
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array<ArrayBuffer> {
  if (a.length === 0) return b.slice();
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

/**
 * Plaintext in, sealed bytes out: with a passphrase, or a key already derived
 * from one. Every stream draws its own nonce prefix, so many files sealed with
 * one key never share a nonce.
 */
export function sealStream(
  secret: string | SealKey,
  options: SealOptions = {},
): TransformStream<Uint8Array, Uint8Array> {
  const derived = typeof secret === "string" ? null : secret;
  const iterations = derived?.iterations ?? options.iterations ?? DEFAULT_ITERATIONS;
  const chunkBytes = derived?.chunkBytes ?? options.chunkBytes ?? DEFAULT_CHUNK_BYTES;
  const salt = derived?.salt ?? crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const prefix = crypto.getRandomValues(new Uint8Array(PREFIX_BYTES));
  let key: CryptoKey;
  let pending: Uint8Array<ArrayBuffer> = new Uint8Array(0);
  let index = 0;

  const frame = async (
    plain: Uint8Array<ArrayBuffer>,
    final: boolean,
  ): Promise<Uint8Array> => {
    if (index > 0xffffffff) throw new SealError("This backup is too large to seal.");
    const cipher = new Uint8Array(
      await crypto.subtle.encrypt(
        {
          name: "AES-GCM",
          iv: nonceFor(prefix, index++),
          additionalData: final ? FINAL : MIDDLE,
        },
        key,
        plain,
      ),
    );
    const out = new Uint8Array(4 + cipher.length);
    new DataView(out.buffer).setUint32(0, cipher.length);
    out.set(cipher, 4);
    return out;
  };

  return new TransformStream({
    async start(controller) {
      key = derived?.key ??
        await deriveKey(secret as string, salt, iterations);
      const header = new Uint8Array(HEADER_BYTES);
      header.set(MAGIC, 0);
      header.set(salt, MAGIC.length);
      const view = new DataView(header.buffer);
      view.setUint32(MAGIC.length + SALT_BYTES, iterations);
      view.setUint32(MAGIC.length + SALT_BYTES + 4, chunkBytes);
      header.set(prefix, MAGIC.length + SALT_BYTES + 8);
      controller.enqueue(header);
    },
    async transform(chunk, controller) {
      pending = concat(pending, chunk);
      // Strictly more than a chunk: whatever is left at the end, even a full
      // chunk's worth, has to go out as the frame marked final.
      while (pending.length > chunkBytes) {
        controller.enqueue(await frame(pending.slice(0, chunkBytes), false));
        pending = pending.slice(chunkBytes);
      }
    },
    async flush(controller) {
      controller.enqueue(await frame(pending, true));
    },
  });
}

/**
 * Keys already derived while opening, by salt and iterations: a backup's
 * attachments share a handful of salts, and deriving for each file would take
 * half a second apiece.
 */
export type UnsealKeys = Map<string, CryptoKey>;

/** Sealed bytes in, plaintext out. Throws [SealError] with a readable reason. */
export function unsealStream(
  passphrase: string,
  keys: UnsealKeys = new Map(),
): TransformStream<Uint8Array, Uint8Array> {
  let buffer: Uint8Array<ArrayBuffer> = new Uint8Array(0);
  let key: CryptoKey | null = null;
  let prefix = new Uint8Array(0);
  let chunkBytes = 0;
  let index = 0;
  // The last complete frame, held back until the next one arrives or the
  // stream ends — only then is it known whether it should be the final one.
  let held: Uint8Array<ArrayBuffer> | null = null;

  const open = async (cipher: Uint8Array<ArrayBuffer>, at: number, final: boolean) =>
    new Uint8Array(
      await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: nonceFor(prefix, at),
          additionalData: final ? FINAL : MIDDLE,
        },
        key!,
        cipher,
      ),
    );

  const openMiddle = async (cipher: Uint8Array<ArrayBuffer>): Promise<Uint8Array> => {
    const at = index++;
    try {
      return await open(cipher, at, false);
    } catch {
      throw new SealError(
        at === 0
          ? "That passphrase does not open this backup."
          : "This backup is damaged: part of it does not decrypt.",
      );
    }
  };

  return new TransformStream({
    async transform(chunk, controller) {
      buffer = concat(buffer, chunk);
      if (key === null) {
        // The magic first, and as soon as there are bytes to compare: a short
        // file that is not a backup at all should say so, not claim to be a
        // backup cut short.
        if (!startsLikeMagic(buffer)) {
          throw new SealError("This is not an encrypted Rift backup.");
        }
        if (buffer.length < HEADER_BYTES) return;
        const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.length);
        const iterations = view.getUint32(MAGIC.length + SALT_BYTES);
        chunkBytes = view.getUint32(MAGIC.length + SALT_BYTES + 4);
        if (
          iterations < 1 || iterations > MAX_ITERATIONS || chunkBytes < 1 ||
          chunkBytes > MAX_CHUNK_BYTES
        ) {
          throw new SealError("This backup's header is damaged.");
        }
        const salt = buffer.slice(MAGIC.length, MAGIC.length + SALT_BYTES);
        prefix = buffer.slice(MAGIC.length + SALT_BYTES + 8, HEADER_BYTES);
        const known = `${iterations}:${salt.join(",")}`;
        key = keys.get(known) ?? await deriveKey(passphrase, salt, iterations);
        keys.set(known, key);
        buffer = buffer.slice(HEADER_BYTES);
      }

      while (buffer.length >= 4) {
        const length = new DataView(buffer.buffer, buffer.byteOffset, 4).getUint32(0);
        if (length < TAG_BYTES || length > chunkBytes + TAG_BYTES) {
          throw new SealError("This backup is damaged.");
        }
        if (buffer.length < 4 + length) break;
        const cipher = buffer.slice(4, 4 + length);
        buffer = buffer.slice(4 + length);
        if (held !== null) controller.enqueue(await openMiddle(held));
        held = cipher;
      }
    },
    async flush(controller) {
      if (key === null && !startsLikeMagic(buffer)) {
        throw new SealError("This is not an encrypted Rift backup.");
      }
      if (key === null || held === null || buffer.length > 0) {
        throw new SealError("This backup is incomplete — the file was cut short.");
      }
      const at = index++;
      try {
        controller.enqueue(await open(held, at, true));
      } catch {
        // Opens as a middle frame: the end of the file is missing, not wrong.
        const truncated = await open(held, at, false).then(() => true, () => false);
        if (truncated) {
          throw new SealError("This backup is incomplete — the file was cut short.");
        }
        throw new SealError(
          at === 0
            ? "That passphrase does not open this backup."
            : "This backup is damaged: part of it does not decrypt.",
        );
      }
    },
  });
}
