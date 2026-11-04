// Run: deno test --no-lock --allow-env=BUF_BIGINT_DISABLE --config supabase/functions/moderate_user/deno.json supabase/functions/_shared/
import { assertEquals } from "jsr:@std/assert@1";
import { livePermissionsFor } from "./moderation.ts";
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
