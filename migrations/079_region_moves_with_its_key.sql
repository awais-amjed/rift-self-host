-- ============================================================
-- Rift self-hosted server — 079: a region moves with its key
-- ============================================================
-- Found in the security re-review, Nov 26 2026 (#5).
--
-- An administrator could point a region somewhere else with a plain table
-- update (`UPDATE (label, url)`), and the region kept its key. The edge
-- functions then signed RoomService requests with that key and sent them to
-- the new address: an administrator never given the region's secret could
-- collect admin tokens for the real region, good for ten minutes against
-- every room on it. The default region already refused this
-- (`update_server`: a new `livekit_url` needs its own key and secret).
--
--   * `url` is no longer a column a member may update. A region's address
--     changes through `move_voice_region(node, url, key, secret)`, which takes
--     the key pair with it, as `add_voice_region` does.
--   * An address the functions would send those requests to inside the
--     server is refused on every path, the default's included (it follows
--     `servers.livekit_url`): loopback, link-local (where a cloud keeps its
--     metadata), a name with no dot (a Docker service: `kong`, `db`), a
--     login in the address, and the odd spellings of an IP. A LAN address
--     stays allowed: a local install runs on one. A public name that
--     resolves inside is not caught here, and can only reach a LiveKit
--     API path with a signed body.
--
-- A row already holding such an address is left alone until it is changed.
-- ============================================================

REVOKE UPDATE (url) ON livekit_nodes FROM authenticated;

-- ── Addresses the functions must not be sent to ─────────────
CREATE OR REPLACE FUNCTION app.livekit_url_refused(p_url TEXT) RETURNS BOOLEAN
  LANGUAGE sql IMMUTABLE SET search_path = '' AS $$
  WITH a AS (
    SELECT lower(substring(p_url FROM '^wss?://([^/?#]*)')) AS authority
  ), h AS (
    SELECT authority,
           lower(substring(authority FROM '^(\[[^\]]*\]|[^:]*)')) AS host
      FROM a
  )
  SELECT authority IS NULL
      OR position('@' IN authority) > 0
      OR COALESCE(host, '') = ''
      OR (host !~ '^\[' AND position('.' IN host) = 0)
      OR host ~ '(^|\.)localhost\.?$'
      OR host ~ '^(127|0)\.'
      OR host ~ '^169\.254\.'
      OR host ~ '^0[0-9x]'
      OR host ~ '^\[(::|0|fe[89ab][0-9a-f]*:)'
    FROM h
$$;

COMMENT ON FUNCTION app.livekit_url_refused(TEXT) IS
  'Whether a LiveKit address points inside the server: loopback, link-local, '
  'a name with no dot, a login, an odd spelling of an IP. A LAN address is '
  'not refused.';

-- A definer, so the check runs whoever wrote the row: the service role moves
-- the default region (`update_server`) and holds no grant on `app`.
CREATE OR REPLACE FUNCTION app.refuse_inside_node_url() RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF TG_OP = 'UPDATE' AND NEW.url IS NOT DISTINCT FROM OLD.url THEN
    RETURN NEW;
  END IF;
  IF app.livekit_url_refused(NEW.url) THEN
    RAISE EXCEPTION 'A LiveKit address has to be one people''s apps can reach: '
                    'not localhost, a link-local address or a bare container name'
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS livekit_nodes_reachable_url ON livekit_nodes;
CREATE TRIGGER livekit_nodes_reachable_url
  BEFORE INSERT OR UPDATE OF url ON livekit_nodes
  FOR EACH ROW EXECUTE FUNCTION app.refuse_inside_node_url();

-- ── Moving a region ─────────────────────────────────────────
CREATE OR REPLACE FUNCTION public.move_voice_region(
  p_node    UUID,
  p_url     TEXT,
  p_api_key TEXT,
  p_secret  TEXT
) RETURNS JSONB
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_default BOOLEAN;
BEGIN
  -- One of this server's, asked here: SECURITY DEFINER passes every policy.
  SELECT n.is_default INTO v_default
    FROM livekit_nodes n
   WHERE n.id = p_node AND n.server_id = app.server_id();
  IF NOT FOUND THEN
    RAISE EXCEPTION 'No such region on this server' USING ERRCODE = 'no_data_found';
  END IF;
  IF NOT app.is_admin() THEN
    RAISE EXCEPTION 'Only an administrator may move a region'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF v_default THEN
    RAISE EXCEPTION 'The default region moves with the server''s own LiveKit address'
      USING ERRCODE = 'check_violation';
  END IF;
  IF btrim(COALESCE(p_api_key, '')) = '' OR btrim(COALESCE(p_secret, '')) = '' THEN
    RAISE EXCEPTION 'A new address needs the region''s API key and secret'
      USING ERRCODE = 'check_violation';
  END IF;

  UPDATE livekit_nodes SET url = btrim(p_url) WHERE id = p_node;
  UPDATE livekit_node_secrets
     SET livekit_api_key = btrim(p_api_key), livekit_secret_key = btrim(p_secret)
   WHERE node_id = p_node;

  RETURN (SELECT jsonb_build_object('id', n.id, 'label', n.label, 'url', n.url,
                                    'is_default', n.is_default)
            FROM livekit_nodes n WHERE n.id = p_node);
END $$;

COMMENT ON FUNCTION public.move_voice_region(UUID, TEXT, TEXT, TEXT) IS
  'Point a region at a new LiveKit address, with the key pair it signs with '
  'there. Administrators only; never the default region, which follows '
  'servers.livekit_url.';

REVOKE ALL ON FUNCTION app.livekit_url_refused(TEXT) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION app.refuse_inside_node_url() FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.move_voice_region(UUID, TEXT, TEXT, TEXT) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.move_voice_region(UUID, TEXT, TEXT, TEXT) TO authenticated;
