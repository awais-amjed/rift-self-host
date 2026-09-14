import { assertEquals, assertRejects } from "jsr:@std/assert@1";
import { SealError, sealStream, unsealStream } from "./seal.ts";

/** Quick enough for a test, and small enough chunks to exercise several frames. */
const FAST = { iterations: 1000, chunkBytes: 64 };

async function seal(
  bytes: Uint8Array,
  passphrase = "correct horse",
): Promise<Uint8Array> {
  return new Uint8Array(
    await new Response(
      ReadableStream.from([bytes]).pipeThrough(sealStream(passphrase, FAST)),
    )
      .arrayBuffer(),
  );
}

async function unseal(
  bytes: Uint8Array,
  passphrase = "correct horse",
): Promise<Uint8Array> {
  return new Uint8Array(
    await new Response(ReadableStream.from([bytes]).pipeThrough(unsealStream(passphrase)))
      .arrayBuffer(),
  );
}

function sample(length: number): Uint8Array {
  return Uint8Array.from({ length }, (_, i) => (i * 31) % 256);
}

Deno.test("what goes in comes out, across several chunks", async () => {
  for (const length of [0, 1, 63, 64, 65, 200, 256]) {
    const plain = sample(length);
    assertEquals(await unseal(await seal(plain)), plain, `length ${length}`);
  }
});

Deno.test("a wrong passphrase says so", async () => {
  const sealed = await seal(sample(300));
  await assertRejects(() => unseal(sealed, "wrong"), SealError, "passphrase");
});

Deno.test("a file cut short at a chunk boundary is noticed", async () => {
  // Without the final flag, dropping whole frames from the end would leave a
  // file that opens cleanly and restores half a database.
  const sealed = await seal(sample(300));
  const header = 9 + 16 + 4 + 4 + 8;
  const frame = 4 + 64 + 16;
  const withoutLastFrame = sealed.slice(0, header + frame * 2);
  await assertRejects(() => unseal(withoutLastFrame), SealError, "cut short");
});

Deno.test("a changed byte is noticed", async () => {
  const sealed = await seal(sample(300));
  sealed[sealed.length - 20] ^= 0xff;
  await assertRejects(() => unseal(sealed), SealError);
});

Deno.test("something that is not a sealed backup is refused by name", async () => {
  await assertRejects(
    () => unseal(new TextEncoder().encode("plainly not encrypted at all, just text")),
    SealError,
    "not an encrypted Rift backup",
  );
});
