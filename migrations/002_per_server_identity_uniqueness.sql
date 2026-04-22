-- Migration 003: Make public_key and stable_id unique per-server instead of globally.
--
-- Previously these columns had a global UNIQUE constraint, which prevented the
-- same user identity from joining two different servers on the same Supabase
-- instance. Replacing with composite (server_id, public_key) and
-- (server_id, stable_id) uniqueness allows one identity per (user, server)
-- pair while still preventing duplicate registrations on the same server.

-- Drop old global unique constraints
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_public_key_key;
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_stable_id_key;

-- Add composite unique constraints (per server)
ALTER TABLE users
  ADD CONSTRAINT users_server_public_key_unique UNIQUE (server_id, public_key);

ALTER TABLE users
  ADD CONSTRAINT users_server_stable_id_unique UNIQUE (server_id, stable_id);

