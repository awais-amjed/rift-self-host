import "@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "@supabase/supabase-js";
import { AccessToken, RoomServiceClient } from "livekit-server-sdk";
import { grantSources, moderationMetadata } from "../_shared/moderation.ts";
import DBSchema from "../_shared/schema.ts";
import { corsHeaders } from "../_shared/cors.ts";
import { CustomResponse } from "../_shared/response.ts";
import * as EC from "../_shared/error_codes.ts";
import { authenticateToken, extractBearerToken, isAuthError } from "../_shared/auth.ts";
import {
  claimVoiceNode,
  livekitCredentials,
  nodeKeyPair,
  normaliseHost,
  releaseVoiceNodes,
  voiceUserId,
} from "../_shared/livekit.ts";

const supabase = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
);

/**
 * Open the room on [service], answering whether the region was there.
 *
 * Idempotent — LiveKit is happy to be told to create a room that exists — so
 * this doubles as the liveness check, and a caller can try a second region
 * without having to undo anything.
 */
async function openRoom(
  service: RoomServiceClient,
  room: string,
): Promise<boolean> {
  try {
    await service.createRoom({ name: room });
    return true;
  } catch {
    return false;
  }
}

Deno.serve(async (req) => {
  // Handle CORS preflight requests
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const { channel_id, screen_share, sound_share, device_id, preferred_node_id } =
      await req.json();
    const token = extractBearerToken(req);

    const auth = await authenticateToken(supabase, token);
    if (isAuthError(auth)) return auth;

    if (!channel_id) {
      return CustomResponse.error("Missing required field: channel_id", EC.MISSING_FIELDS);
    }

    // Membership, not just "is it on my server". This checked the server and
    // nothing else, which was harmless while every channel was everybody's and
    // is a hole the moment one is not — for people before bots, since a private
    // voice channel is a call you could walk into by knowing an id.
    //
    // `visible_channels` is the same answer 020's policies give; asking the
    // database rather than reimplementing the rule here is the whole point of
    // 021.
    //
    // `channel_joinable_by` rather than `channel_visible_to` (037): a summoned
    // bot is in the room without being of it. It may take a token for this one
    // voice channel and nothing else — it still cannot list the channel, read
    // its roster or post in it, because every other caller asks
    // `app.sees_channel` and still gets no.
    //
    // ── and everything it needs to decide, asked at once ──
    //
    // Nothing here depends on anything else here: whether the channel admits
    // them, whether they may connect, whether they may share, who they are,
    // and the server's LiveKit credentials are five independent reads. They
    // used to be five round trips one after another, and this is the function
    // every join goes through — a channel that fills up after a raid or an
    // event pays them once per person, in series, each.
    //
    // The *answers* are still weighed in the order they always were, below,
    // so the refusal a caller gets is unchanged. Asking a question whose
    // answer is thrown away costs a query and reveals nothing: none of these
    // writes anything, and nothing is returned on a refusal.
    const wantsShare = screen_share === true || sound_share === true;
    const [
      { data: visible, error: visibleError },
      { data: mayConnect },
      { data: mayShare },
      { data: userData, error: userError },
      credentials,
      { data: limitsRow },
    ] = await Promise.all([
      supabase.rpc("channel_joinable_by", { p_channel: channel_id, p_user: auth.userId }),
      supabase.rpc("user_has_permission", { p_user: auth.userId, p_name: "CONNECT" }),
      wantsShare
        ? supabase.rpc("user_has_permission", { p_user: auth.userId, p_name: "SCREEN_SHARE" })
        : Promise.resolve({ data: null }),
      supabase
        .from(DBSchema.users.tableName)
        .select(
          `${DBSchema.users.displayName}, ${DBSchema.users.isMuted}, ` +
            `${DBSchema.users.isDeafened}, ${DBSchema.users.isBot}`,
        )
        .eq(DBSchema.users.id, auth.userId)
        .single(),
      livekitCredentials(supabase, auth.serverId),
      supabase
        .from(DBSchema.servers.tableName)
        .select(`${DBSchema.servers.maxVoiceParticipants}, ${DBSchema.servers.maxShareMbps}`)
        .eq(DBSchema.servers.id, auth.serverId)
        .single(),
    ]);

    if (visibleError) {
      return CustomResponse.error("Error reading channel access", EC.DB_ERROR, visibleError);
    }
    if (visible !== true) {
      // Not "forbidden": a room you cannot see should not confirm it exists.
      return CustomResponse.error("Channel not found", EC.CHANNEL_NOT_FOUND);
    }

    // `CONNECT`, and `SCREEN_SHARE` for the second connection. The moderation
    // flags below decide what a token may carry once you are in the room; these
    // decide whether there is a token at all.
    if (mayConnect !== true) {
      return CustomResponse.error("You cannot join voice channels", EC.PERMISSION_DENIED);
    }
    // Sharing sound is the same capability as sharing a screen — a screen
    // share already carries the app's audio, so a separate permission would
    // only let a member be denied the quieter half of what they can already
    // do. One permission, two kinds of share.
    if (wantsShare && mayShare !== true) {
      return CustomResponse.error("You cannot share here", EC.PERMISSION_DENIED);
    }

    const room = channel_id;

    if (userError || !userData) {
      return CustomResponse.error("User not found", EC.USER_NOT_FOUND, userError);
    }

    const userRecord = userData as Record<string, any>;

    // Identity = "<userId>~<deviceId>" (+ "_screenshare" for the screen-share
    // connection, or "_soundshare" for the sound-share one — a separate suffix
    // so one member can do both at once; two connections claiming the same
    // identity would kick each other). The device segment lets the same user
    // join from multiple
    // devices without a LiveKit identity collision — without it, a second
    // device joining the same room kicks the first one out. The userId prefix
    // is always server-controlled (from auth), so a client-supplied device_id
    // can never spoof another user; we still sanitise it to keep the identity
    // parseable (userId is split off on the first "~").
    const deviceSuffix =
      (typeof device_id === "string" ? device_id : "").replace(/[^a-zA-Z0-9]/g, "").slice(0, 16) ||
      "default";
    let identity = `${auth.userId}~${deviceSuffix}`;

    if (screen_share === true) {
      identity = `${identity}_screenshare`;
    } else if (sound_share === true) {
      identity = `${identity}_soundshare`;
    }

    const displayName = userRecord[DBSchema.users.displayName];
    const isMuted: boolean = userRecord[DBSchema.users.isMuted] === true;
    const isDeafened: boolean = userRecord[DBSchema.users.isDeafened] === true;
    const isBot: boolean = userRecord[DBSchema.users.isBot] === true;

    // A bot publishes; it does not hear (BOTS.md §6b, migration 031).
    //
    // This function never asked what the caller was, and `@everyone` carries
    // CONNECT and SPEAK — so a bot invited to a server could sit in a call and
    // receive everybody's audio, with nothing shown in the room. Voice was the
    // one place "a bot hears what you tell it, not what you say" was false.
    //
    // A music bot only publishes, so the strict default costs it nothing. A bot
    // that genuinely needs to listen gets an explicit per-channel grant, and
    // unlike §6's key grant this one is honestly reversible: subscription is a
    // permission rather than arithmetic, so revoking stops the audio mid-call.
    // Calls are end-to-end encrypted (migrations 031-032), and a bot publishing
    // with `encryptionType: kNone` would be one every member's client skips the
    // frame cryptor for — its audio in the clear, inside the room built so that
    // could not happen. So a bot needs a media key before it needs a token, and
    // a member's client is the only thing that can produce one.
    //
    // Refusing until it has one is the honest failure: the bot is told to wait
    // rather than joining and being inaudible for reasons nothing reports.
    if (isBot) {
      const { data: botKey } = await supabase
        .from("bot_voice_keys")
        .select("bot_id")
        .eq("channel_id", channel_id)
        .eq("bot_id", auth.userId)
        .limit(1)
        .maybeSingle();
      if (!botKey) {
        return CustomResponse.error(
          "No media key for this channel yet — a member has to be here first",
          EC.KEY_NOT_READY,
        );
      }
    }

    let mayListen = true;
    if (isBot) {
      const { data: grant, error: grantError } = await supabase
        .from("bot_voice_grants")
        .select("bot_id")
        .eq("channel_id", channel_id)
        .eq("bot_id", auth.userId)
        .maybeSingle();
      if (grantError) {
        return CustomResponse.error("Error reading bot voice access", EC.DB_ERROR, grantError);
      }
      // Fail closed. An unreadable grant is a bot that cannot hear, never one
      // that can — the failure people notice is the safe one.
      mayListen = grant !== null;
    }

    // The API secret lives in `server_secrets`, which no client can read —
    // minting this token is the only reason anything reads it, and it is why
    // this endpoint stays an edge function.
    if (!credentials) {
      return CustomResponse.error("LiveKit credentials not configured for this server", EC.SERVER_CREDENTIALS_MISSING);
    }

    const limits = (limitsRow ?? {}) as Record<string, any>;
    const maxVoice = Number(limits[DBSchema.servers.maxVoiceParticipants] ?? 0);
    const maxShareMbps = Number(limits[DBSchema.servers.maxShareMbps] ?? 0);

    // The channel's pinned region, needed only to know whether a failure to
    // open the room is the *pin* failing — which is the one case that falls
    // back to automatic below.
    const { data: channelRow } = await supabase
      .from(DBSchema.channels.tableName)
      .select(DBSchema.channels.livekitNodeId)
      .eq(DBSchema.channels.id, channel_id)
      .maybeSingle();
    const pinnedNodeId =
      (channelRow as Record<string, any> | null)?.[
        DBSchema.channels.livekitNodeId
      ] as string | null ?? null;

    // Which LiveKit this call is on. A server may have several, and a room
    // lives on exactly one of them — so this is decided once, by whoever gets
    // here first, and everybody afterwards is told where that was.
    //
    // `preferred_node_id` is what the client measured. It is a suggestion:
    // the database checks it is really one of this server's nodes, and it
    // only counts at all when the channel is not pinned and there is no call
    // up yet. A client that names somebody else's node, or a stale one, is
    // answered with the default rather than refused — being sent to a working
    // node is better than being told no.
    let node = await claimVoiceNode(supabase, channel_id, preferred_node_id ?? null);
    let nodeUrl = node?.url ?? credentials.url;
    let nodeHost = node ? normaliseHost(node.url) : credentials.host;

    // **The key belongs to the node, not to the server.** Every added region
    // signs with its own pair and only the default node uses the server's, so
    // this is read after the node is known — and again if the fallback below
    // lands somewhere else, because a token is only valid on the box it was
    // signed for.
    //
    // Null means there is no key for that region, which the schema does not
    // allow to happen. If it somehow has, the region is unusable rather than
    // quietly run on the server's pair, and everything below treats it as a
    // region that did not answer.
    let pair = await nodeKeyPair(supabase, node, credentials);

    // Pre-create the LiveKit room server-side (idempotent — safe to call even if
    // the room already exists). This means clients never need roomCreate: true;
    // the edge function is the only thing that can create rooms.
    let roomService = pair
      ? new RoomServiceClient(nodeHost, pair.apiKey, pair.apiSecret)
      : null;

    // How full the call is (migration 028), asked only when there is a limit
    // to compare it against — a server that has not set one pays nothing.
    //
    // **People, not connections.** A screen share is a second connection held
    // by somebody already in the room, so `voiceUserId` drops it; an operator
    // who typed 50 meant fifty people, and a limit that counted sockets would
    // tell a member the call was full when they tried to share their screen.
    // For the same reason a second connection from somebody already counted
    // is always let through: they are not a new arrival.
    //
    // Not a perfect gate, and does not need to be. Two people arriving in the
    // same instant can both pass, and a member holding an unexpired token
    // from earlier can rejoin without asking. What it does stop is a channel
    // growing without bound, because every genuinely new arrival needs a
    // fresh token and every one of those is counted.
    if (maxVoice > 0 && !isBot && roomService) {
      try {
        const present = new Set(
          (await roomService.listParticipants(room))
            .map((p) => voiceUserId(p.identity))
            .filter((id): id is string => id !== null),
        );
        if (present.size >= maxVoice && !present.has(auth.userId)) {
          return CustomResponse.error(
            `This call is full — it takes ${maxVoice} ` +
              `${maxVoice === 1 ? "person" : "people"}`,
            EC.VOICE_CHANNEL_FULL,
          );
        }
      } catch {
        // No room yet, or LiveKit did not answer. An empty call is not a full
        // one, and refusing everybody because the count could not be had
        // would turn a bandwidth limit into an outage.
      }
    }
    // Opening the room is also how the region is asked whether it is there.
    //
    // **A pinned region that does not answer falls back to automatic, for
    // this call only.** The pin is an operator's decision and stays in the
    // channel's row — the settings dialog goes on showing it, and when the
    // region comes back the next call goes there again with nobody having
    // touched anything. What must not happen is everybody being stranded in
    // the meantime because the person who could repin is asleep.
    //
    // Only from the pin, and only once. An automatic choice that fails has
    // nothing better to fall back to, and a second failure is a server with
    // no region answering at all.
    let opened = roomService ? await openRoom(roomService, room) : false;

    if (!opened && node && pinnedNodeId && node.id === pinnedNodeId) {
      await releaseVoiceNodes(supabase, [channel_id]).catch(() => {});
      // **Nothing suggested**, which is what makes this a fallback rather
      // than a second go at the same answer. Passing the client's measured
      // preference here sent the call straight back to the region that had
      // just refused it: the pin was ignored, so the preference was next in
      // line — and a region whose *key* is wrong answers the probe perfectly
      // well, so it is still the one the client measured as best. Without a
      // preference the claim falls through to the default node, which is the
      // honest meaning of "put this call up somewhere that works".
      const fallback = await claimVoiceNode(supabase, channel_id, null, true);
      // Against the region that just failed, not against the pin. They are
      // the same here, and naming the failure is what stays true if this ever
      // runs for a region that was not pinned.
      if (fallback && fallback.id !== node.id) {
        node = fallback;
        nodeUrl = fallback.url;
        nodeHost = normaliseHost(fallback.url);
        // Another region, so another key — read again rather than reused, or
        // the room is opened with a pair this box never accepts.
        pair = await nodeKeyPair(supabase, fallback, credentials);
        roomService = pair
          ? new RoomServiceClient(nodeHost, pair.apiKey, pair.apiSecret)
          : null;
        opened = roomService ? await openRoom(roomService, room) : false;
      }
    }

    if (!opened) {
      // The region is not answering. Two things follow, and the second is the
      // one that matters: let go of the claim.
      //
      // Claiming happens before the room is opened, because the claim is what
      // stops two simultaneous joiners opening the call in two places. So a
      // region that is down leaves a claim naming it — and a claim is the
      // *first* rule of resolution, above the pin and above what anybody
      // measured. Left behind, it would go on sending people to a node that
      // is not there long after an automatic channel would otherwise have
      // picked the one that is.
      //
      // A pinned channel will simply claim it again and fail again, which is
      // correct: the operator said where these calls go, and the answer to a
      // region being down is to fix it or to pin somewhere else.
      if (node) {
        await releaseVoiceNodes(supabase, [channel_id]).catch(() => {});
      }
      return CustomResponse.error(
        node
          ? `${node.label} is not answering, so this call could not be opened`
          : "Failed to ensure LiveKit room exists",
        EC.UNEXPECTED_ERROR,
      );
    }

    // Create LiveKit access token. Moderation flags are enforced here — a
    // server-muted user's token cannot publish microphone audio and a
    // deafened user's token cannot subscribe, so the state survives rejoins
    // and cannot be bypassed client-side. The flags also ride along as
    // participant metadata so every client can render the moderation state.
    // Non-null past the check above: the room was opened, which needed it.
    const at = new AccessToken(pair!.apiKey, pair!.apiSecret, {
      identity,
      name: displayName,
      ttl: "1h",
      metadata: moderationMetadata(isMuted, isDeafened),
    });

    at.addGrant({
      roomCreate: false,  // room is always pre-created above; clients must not create arbitrary rooms
      roomJoin: true,
      room,
      canPublish: true,
      // undefined = all sources. Deafened denies the mic as well as the ears.
      canPublishSources: grantSources(isMuted, isDeafened),
      // Never on a share connection. A share only publishes — the desktop's
      // is a Rust session that listens for nothing — and the roster skips
      // `_screenshare` / `_soundshare` identities, because they are the same
      // person's second connection. So a share token that could subscribe
      // was a way to sit in a call hearing everything while appearing
      // nowhere: ask for a screen share, publish nothing.
      canSubscribe: !isDeafened && mayListen && !wantsShare,
      // Lets a client publish its own state as participant attributes — today
      // just "deafened", which nothing else broadcasts: a muted microphone is
      // visible as an unpublished track, but deafening is a decision made
      // entirely inside the listener's client, and the roster has no way to
      // show it otherwise.
      //
      // It also lets a client rewrite its own metadata, which is where the
      // moderation flags ride. That is cosmetic and it is the only thing it
      // is: what a muted member may actually publish is `canPublishSources`
      // above, which is minted here and cannot be touched from the client. The
      // worst case is somebody hiding their own "muted by a moderator" badge
      // from other people's rosters.
      canUpdateOwnMetadata: true,
      // A bot is never a room admin. `isChannelManager` is a cached boolean a
      // bot could hold if somebody handed it a moderator role, and roomAdmin is
      // the power to mute and remove people in a call — a thing a bot should be
      // given deliberately if ever, not as a side effect of a text permission.
      roomAdmin: auth.isChannelManager && !isBot,
    });

    const livekitToken = await at.toJwt();

    // Return the identity so the desktop screen-share path (which connects via
    // the Rust SDK) uses the exact identity embedded in this token instead of
    // reconstructing it client-side.
    // `max_share_mbps` rides along with the token rather than only living on
    // the server row, so the client has it at the moment it needs it and a
    // change takes effect on the next join rather than the next sync. It is a
    // number the client keeps: a LiveKit token has nowhere to put a bitrate,
    // so there is nothing here to clamp, and nothing server-side throttles a
    // publisher either. Deliberate — this is a limit about cost rather than
    // about trust, and the case it exists for is somebody left on the 10 Mbps
    // default who does not know it costs that per watcher.
    // `livekit_url` rides along with the token for the same reason
    // `max_share_mbps` does: the client has it at the moment it needs it, and
    // it is this function that decides it. A client that takes its address
    // from here rather than from `servers.livekit_url` can be sent to a
    // different node per channel without being rebuilt — see
    // `LiveKitCredentials.url`. Older clients ignore the field and read the
    // server row, which is the same address today.
    return CustomResponse.success({
      token: livekitToken,
      identity,
      livekit_url: nodeUrl,
      max_share_mbps: maxShareMbps,
    });
  } catch (err) {
    return CustomResponse.error(`Unexpected error: ${err}`, EC.UNEXPECTED_ERROR, err);
  }
});
