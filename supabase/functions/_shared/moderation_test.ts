// Run: deno test --no-lock --allow-env=BUF_BIGINT_DISABLE --config supabase/functions/moderate_user/deno.json supabase/functions/_shared/
import { assertEquals } from "jsr:@std/assert@1";
import { TrackSource } from "livekit-server-sdk";
import { holdsAlready, livePermissionsFor, micHeldBack } from "./moderation.ts";
import { watchGrant } from "./watch.ts";

// LiveKit replaces a connection's whole permission set on update, so a right
// left out of `livePermissionsFor` is taken away by any moderator's click.
// Voice and share tokens are minted able to set their own attributes
// (`get_channel_token`, `get_dm_call_token`): deafened, push-to-talk and
// what is watched ride there.
for (const kind of ["voice", "share"] as const) {
  Deno.test(`a moderated ${kind} connection still sets its own attributes`, () => {
    for (const [muted, deafened] of [[true, false], [false, true], [false, false]]) {
      assertEquals(livePermissionsFor(kind, muted, deafened).canUpdateMetadata, true);
    }
  });
}

Deno.test("a moderated watch connection keeps what it was minted with", () => {
  const minted = watchGrant("room", true);
  const live = livePermissionsFor("watch", true, false);
  assertEquals(live.canUpdateMetadata, minted.canUpdateOwnMetadata);
  assertEquals(live.hidden, minted.hidden);
  assertEquals(live.canPublish, minted.canPublish);
  assertEquals(live.canPublishData, minted.canPublishData);
});

// `set_channel_override` updates only the connections whose microphone is in
// the wrong state, so it has to read the two encodings the same way the
// pushes write them: empty is every source, the muted list holds it back.
Deno.test("a connection's microphone is read the way it was pushed", () => {
  assertEquals(micHeldBack([]), false);
  assertEquals(micHeldBack(undefined), false);
  assertEquals(micHeldBack(livePermissionsFor("voice", true, false).canPublishSources), true);
  assertEquals(micHeldBack(livePermissionsFor("voice", false, false).canPublishSources), false);
  assertEquals(micHeldBack([TrackSource.MICROPHONE, TrackSource.CAMERA]), false);
});

// A soundboard press is the only data packet a member sends, so
// `canPublishData` is the soundboard (`_shared/call_rights.ts`). A push states
// it as the channel has it; one that forgot would take it, never give it.
Deno.test("a pushed connection sends packets only with the soundboard", () => {
  for (const [muted, deafened] of [[true, false], [false, true], [false, false]]) {
    assertEquals(livePermissionsFor("voice", muted, deafened, true, true).canPublishData, true);
    assertEquals(livePermissionsFor("voice", muted, deafened, true, false).canPublishData, false);
    assertEquals(livePermissionsFor("voice", muted, deafened).canPublishData, false);
    // A share sends none, as minted, whatever the channel says.
    assertEquals(livePermissionsFor("share", muted, deafened, true, true).canPublishData, false);
  }
});

// A connection already holding what a push would give is left alone, and one
// holding more is pushed: that is how a token kept from before a mute, a
// Listen-only or a lost soundboard is caught when it is used to rejoin.
Deno.test("a connection holding more than it should is not left alone", () => {
  const wanted = livePermissionsFor("voice", true, false, true, false);
  assertEquals(holdsAlready("voice", wanted, wanted), true);
  // Minted before the mute: every source, packets, ears.
  const stale = livePermissionsFor("voice", false, false, true, true);
  assertEquals(holdsAlready("voice", stale, wanted), false);
  assertEquals(holdsAlready("voice", { ...wanted, canPublishData: true }, wanted), false);
  assertEquals(holdsAlready("voice", { ...wanted, canPublishSources: [] }, wanted), false);
  // Deafened since: the ears go too.
  const deaf = livePermissionsFor("voice", false, true, true, false);
  assertEquals(holdsAlready("voice", { ...deaf, canSubscribe: true }, deaf), false);
  // A watch connection has no microphone to compare.
  const watch = livePermissionsFor("watch", true, false);
  assertEquals(holdsAlready("watch", watch, watch), true);
  assertEquals(holdsAlready("watch", undefined, livePermissionsFor("watch", false, true)), true);
});
