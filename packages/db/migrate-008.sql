-- SentinelForge migration 008 — firmware bytes.
--
-- schema.sql's `firmware` row is metadata only (hash, size, version, device).
-- Real uploads need the image itself, and list queries must not drag megabytes
-- along, so the bytes sit in their own table keyed by firmware id.
--
-- Round 34: encrypted_at_rest is no longer a schema default. The API seals each
-- blob with AES-256-GCM when FIRMWARE_ENC_KEY is configured and writes the
-- actual outcome to that column, so 'SFENC1'-prefixed rows are ciphertext and
-- unsealed rows say encrypted_at_rest=false.
CREATE TABLE IF NOT EXISTS firmware_blobs (
  firmware_id UUID PRIMARY KEY REFERENCES firmware(id) ON DELETE CASCADE,
  data BYTEA NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
