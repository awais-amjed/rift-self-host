-- ============================================================
-- Rift self-hosted server — 011: point push at a name, not a host
-- ============================================================
-- Migration 010 stored whatever address the admin's client handed over, which
-- at the time was the relay's *current* home. That made the hosting choice
-- permanent: moving the relay would have meant every operator re-enabling
-- notifications, and the ones who never noticed would simply have stopped
-- waking anyone.
--
-- The address is a name Rift owns instead. What answers behind it — a Supabase
-- edge function, a Worker, a VPS — is free to change as often as it likes, and
-- no server ever learns that it did.
--
-- Safe to run repeatedly, and a no-op on a server that has never turned push
-- on. An operator who applies this while push is enabled keeps working across
-- the move without touching anything; one who doesn't gets it the next time
-- their admin re-enables.

UPDATE push_config
   SET endpoint   = 'https://push.joinrift.app',
       updated_at = now()
 WHERE endpoint IS DISTINCT FROM 'https://push.joinrift.app';
