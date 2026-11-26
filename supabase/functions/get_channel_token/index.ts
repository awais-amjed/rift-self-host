import "@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "@supabase/supabase-js";
import { AccessToken, RoomServiceClient } from "livekit-server-sdk";
import { moderationMetadata, publishSources } from "../_shared/moderation.ts";
import { corsHeaders } from "../_shared/cors.ts";
import { CustomResponse } from "../_shared/response.ts";
import * as EC from "../_shared/error_codes.ts";
import { extractBearerToken } from "../_shared/auth.ts";
import { verifyJwt } from "../_shared/jwt.ts";
import { admitWatcher, WATCH_TOKEN_TTL, watchGrant, watchIdentity } from "../_shared/watch.ts";
import {
  claimVoiceNode,
  KeyPair,
  LiveKitCredentials,
  LiveKitNode,
  nodeKeyPair,
  normaliseHost,
  preferredNode,
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

/**
 * The answer for a refusal `voice_join_facts` gave, in the words and codes
 * this function always answered with, or null for `ok`.
 */
function refusal(reason: string): Response | null {
  switch (reason) {
    case "ok":
      return null;
    case "user_not_found":
      return CustomResponse.error("User not found", EC.USER_NOT_FOUND);
    case "user_banned":
      return CustomResponse.error("User is banned", EC.USER_BANNED);
    case "channel_not_found":
      // Not "forbidden": a room you cannot see should not confirm it exists.
      return CustomResponse.error("Channel not found", EC.CHANNEL_NOT_FOUND);
    case "no_connect":
      return CustomResponse.error("You cannot join this voice channel", EC.PERMISSION_DENIED);
    case "no_share":
      // Sharing sound is the same capability as sharing a screen — a screen
      // share already carries the app's audio, so a separate permission would
      // only let a member be denied the quieter half of what they can already
      // do. One permission, two kinds of share.
      return CustomResponse.error("You cannot share here", EC.PERMISSION_DENIED);
    case "bot_cannot_watch":
      // A bot hears on its one connection, by an explicit grant; a hidden
      // second one would be listening nobody sees.
      return CustomResponse.error("A bot cannot watch", EC.PERMISSION_DENIED);
    case "key_not_ready":
      return CustomResponse.error(
        "No media key for this channel yet — a member has to be here first",
        EC.KEY_NOT_READY,
      );
    case "credentials_missing":
      return CustomResponse.error(
        "LiveKit credentials not configured for this server",
        EC.SERVER_CREDENTIALS_MISSING,
      );
    case "not_in_call":
      return CustomResponse.error("Join the call before watching in it", EC.USER_NOT_IN_VOICE);
    case "not_voice":
      // A call is only ever in a voice channel. Without this a text channel's
      // id made a room too, which nothing lists and nothing moderates.
      return CustomResponse.error("Not a voice channel", EC.CHANNEL_NOT_FOUND);
    case "claim_failed":
      return CustomResponse.error("Could not decide where this call is held", EC.VOICE_SERVER_UNREACHABLE);
    default:
      return CustomResponse.error("Error reading channel access", EC.DB_ERROR);
  }
}

Deno.serve(async (req) => {
  // Handle CORS preflight requests
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const { channel_id, screen_share, sound_share, watch, device_id, preferred_node_id } =
      await req.json();
    const token = extractBearerToken(req);
    if (!token) {
      return CustomResponse.error("Missing required field: token", EC.TOKEN_MISSING);
    }
    // The JWT is checked here, against the stack's keys; who the caller is on
    // this server (a member, banned, a server being deleted) is the
    // database's first answer below.
    const userId = await verifyJwt(token);
    if (!userId) {
      return CustomResponse.error("Invalid or expired token", EC.TOKEN_INVALID);
    }

    if (!channel_id) {
      return CustomResponse.error("Missing required field: channel_id", EC.MISSING_FIELDS);
    }

    const wantsShare = screen_share === true || sound_share === true;
    // A watch connection only receives (`_shared/watch.ts`); one that also
    // shared would be a hidden publisher.
    const wantsWatch = watch === true;
    if (wantsWatch && wantsShare) {
      return CustomResponse.error("A connection either shares or watches", EC.PERMISSION_DENIED);
    }

    // ── Everything it decides from, in one call ──
    //
    // `voice_join_facts` (065) weighs what this function used to ask in eleven
    // round trips, in the order it weighed them, so the refusal a caller gets
    // is unchanged:
    //
    //   * membership: no row, a ban, a server being deleted;
    //   * the door, `channel_joinable_by` rather than `channel_visible_to`: a
    //     summoned bot is in the room without being of it, and may take a
    //     token for this one voice channel and nothing else;
    //   * the channel's bits, not the server's (`channel_overrides`), so a
    //     stage can keep everyone but its speakers quiet: `CONNECT`, and
    //     `SCREEN_SHARE` for a share, decide whether there is a token at all;
    //     `SPEAK` and the soundboard decide what it carries;
    //   * a bot: no watching, a media key before a token, and ears only by a
    //     grant (below);
    //   * the server's LiveKit, and its limits;
    //   * where the call is: for a watch, read; otherwise claimed.
    //
    // The claim is the one write, and it comes after every refusal the
    // database can give. The keys come back with it: this function is what
    // signs, and the only thing that may hold them.
    const kind = wantsWatch ? "watch" : wantsShare ? "share" : "voice";
    const { data: factsData, error: factsError } = await supabase.rpc("voice_join_facts", {
      p_user: userId,
      p_channel: channel_id,
      p_kind: kind,
      p_preferred: preferredNode(preferred_node_id),
    });
    if (factsError) {
      return CustomResponse.error("Error reading channel access", EC.DB_ERROR, factsError);
    }
    const facts = (factsData ?? {}) as Record<string, any>;
    const refused = refusal(String(facts.reason ?? ""));
    if (refused) return refused;

    const room = channel_id;

    // Identity = "<userId>~<deviceId>" (+ "_screenshare" for the screen-share
    // connection, "_soundshare" for the sound-share one, or "_watch" for the
    // watch connection — a separate suffix each so one member can hold them
    // all at once; two connections claiming the same identity would kick
    // each other). The device segment lets the same user
    // join from multiple
    // devices without a LiveKit identity collision — without it, a second
    // device joining the same room kicks the first one out. The userId prefix
    // is always server-controlled (from auth), so a client-supplied device_id
    // can never spoof another user; we still sanitise it to keep the identity
    // parseable (userId is split off on the first "~").
    const deviceSuffix =
      (typeof device_id === "string" ? device_id : "").replace(/[^a-zA-Z0-9]/g, "").slice(0, 16) ||
      "default";
    const voiceIdentity = `${userId}~${deviceSuffix}`;
    let identity = voiceIdentity;

    if (screen_share === true) {
      identity = `${identity}_screenshare`;
    } else if (sound_share === true) {
      identity = `${identity}_soundshare`;
    }

    const displayName = facts.display_name as string;
    const isMuted: boolean = facts.is_muted === true;
    const isDeafened: boolean = facts.is_deafened === true;
    const isBot: boolean = facts.is_bot === true;
    const maySpeak: boolean = facts.speak === true;
    const maySoundboard: boolean = facts.soundboard === true;
    // Missing from a database before 078: no screen on the voice connection,
    // which is the refusal it was meant to give. A share connection got past
    // `no_share`, so it holds the bit whatever the answer says.
    const mayShareScreen: boolean = facts.screen_share === true || wantsShare;

    // A bot publishes; it does not hear (BOTS.md §6b).
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
    // Calls are end-to-end encrypted, and a bot publishing
    // with `encryptionType: kNone` would be one every member's client skips the
    // frame cryptor for — its audio in the clear, inside the room built so that
    // could not happen. So a bot needs a media key before it needs a token
    // (`key_not_ready`), and a member's client is the only thing that can
    // produce one.
    //
    // Fail closed: anything but a grant read as there is a bot that cannot
    // hear, never one that can — the failure people notice is the safe one.
    const mayListen = !isBot || facts.may_listen === true;

    // The API secret lives in `server_secrets`, which no client can read —
    // minting this token is the only reason anything reads it, and it is why
    // this endpoint stays an edge function.
    const credentialsRow = facts.credentials as Record<string, string>;
    const credentials: LiveKitCredentials = {
      host: normaliseHost(credentialsRow.url),
      apiKey: credentialsRow.api_key,
      apiSecret: credentialsRow.api_secret,
      url: credentialsRow.url,
    };

    const maxVoice = Number(facts.max_voice_participants ?? 0);
    const maxShareMbps = Number(facts.max_share_mbps ?? 0);

    // ── A watch connection ──────────────────────────────────
    //
    // Into the call this device is already in, so nothing below applies: no
    // region is chosen, no room opened, nobody counted. Where the call is
    // comes from `voice_rooms`, read rather than claimed, and the voice
    // connection being in that room is the condition for the token at all.
    if (wantsWatch) {
      const node = facts.watch as Record<string, string>;
      const service = new RoomServiceClient(normaliseHost(node.url), node.api_key, node.api_secret);
      if (!(await admitWatcher(service, room, voiceIdentity))) {
        return CustomResponse.error("Join the call before watching in it", EC.USER_NOT_IN_VOICE);
      }
      const watchToken = new AccessToken(node.api_key, node.api_secret, {
        identity: watchIdentity(voiceIdentity),
        name: displayName,
        ttl: WATCH_TOKEN_TTL,
      });
      watchToken.addGrant(watchGrant(room, !isDeafened && mayListen));
      return CustomResponse.success({
        token: await watchToken.toJwt(),
        identity: watchIdentity(voiceIdentity),
        livekit_url: node.url,
        max_share_mbps: maxShareMbps,
      });
    }

    // The channel's pinned region, needed only to know whether a failure to
    // open the room is the *pin* failing — which is the one case that falls
    // back to automatic below.
    const pinnedNodeId = (facts.pinned_node_id as string | null) ?? null;

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
    const claimed = facts.node as Record<string, any> | null;
    let node: LiveKitNode | null = claimed
      ? { id: claimed.id, url: claimed.url, label: claimed.label ?? "", isDefault: claimed.is_default === true }
      : null;
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
    let pair: KeyPair | null = !claimed
      ? credentials
      : claimed.api_key && claimed.api_secret
      ? { apiKey: claimed.api_key, apiSecret: claimed.api_secret }
      : null;

    // Pre-create the LiveKit room server-side (idempotent — safe to call even if
    // the room already exists). This means clients never need roomCreate: true;
    // the edge function is the only thing that can create rooms.
    let roomService = pair
      ? new RoomServiceClient(nodeHost, pair.apiKey, pair.apiSecret)
      : null;

    // How full the call is, asked only when there is a limit
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
        if (present.size >= maxVoice && !present.has(userId)) {
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
      const fallback = await claimVoiceNode(supabase, channel_id, null, true)
        .catch(() => null);
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
        EC.VOICE_SERVER_UNREACHABLE,
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
      // Named one by one (`publishSources`). Deafened denies the mic as well
      // as the ears. Without `SPEAK` here the microphone goes as it does for
      // a muted member, though the metadata says nothing: nobody muted them,
      // and the badge would say somebody had. Without `SCREEN_SHARE` the
      // screen goes, which phones and browsers publish on this connection.
      // Unreadable is not allowed, failing closed.
      canPublishSources: publishSources(isMuted || maySpeak !== true, isDeafened, mayShareScreen),
      // Never on a share connection. A share only publishes — the desktop's
      // is a Rust session that listens for nothing — and the roster skips
      // `_screenshare` / `_soundshare` identities, because they are the same
      // person's second connection. So a share token that could subscribe
      // was a way to sit in a call hearing everything while appearing
      // nowhere: ask for a screen share, publish nothing.
      canSubscribe: !isDeafened && mayListen && !wantsShare,
      // A soundboard press is a data packet that every listener plays for
      // itself, and the only one a member sends, so this is what keeps the
      // soundboard from someone the channel takes it from: LiveKit drops
      // their packets before anyone hears them. Both bits, as the app asks
      // (`mayUseSoundboard`), and never on a share connection, which sends
      // none. Left out, a grant means "may", which is how a member whose
      // own app was told otherwise could still press.
      canPublishData: !wantsShare && maySoundboard === true && maySpeak === true,
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
      // Nobody is a room admin. RoomService admin is the power to mute and
      // remove anybody in the call, admins and the owner included, to lift a
      // server mute or deafen from yourself, and to send packets as anybody —
      // and a token keeps it for its whole life, past a demotion or a ban.
      // The app never uses it: every moderation act goes through an edge
      // function, which asks the database first.
      roomAdmin: false,
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
    return CustomResponse.error("Unexpected error", EC.UNEXPECTED_ERROR, err);
  }
});
