-- Add WhatsApp, Discord, and MS Teams channel settings.
ALTER TABLE settings
ADD COLUMN allow_whatsapp INTEGER NOT NULL DEFAULT 0;

ALTER TABLE settings
ADD COLUMN whatsapp_allow_from TEXT NOT NULL DEFAULT '';

ALTER TABLE settings
ADD COLUMN allow_discord INTEGER NOT NULL DEFAULT 0;

ALTER TABLE settings
ADD COLUMN discord_allow_from TEXT NOT NULL DEFAULT '';

ALTER TABLE settings
ADD COLUMN allow_msteams INTEGER NOT NULL DEFAULT 0;

ALTER TABLE settings
ADD COLUMN msteams_allow_from TEXT NOT NULL DEFAULT '';