ALTER TABLE public.auth_passkey_credential
    ADD COLUMN IF NOT EXISTS name varchar NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS device_info jsonb NOT NULL DEFAULT '{}'::jsonb;
