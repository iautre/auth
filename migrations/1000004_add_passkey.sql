CREATE TABLE IF NOT EXISTS public.auth_passkey_credential
(
    id               bigserial PRIMARY KEY,
    user_id          bigint NOT NULL REFERENCES public.auth_user (id) ON DELETE CASCADE,
    name             varchar NOT NULL DEFAULT '',
    device_info      jsonb NOT NULL DEFAULT '{}'::jsonb,
    credential_id    bytea NOT NULL UNIQUE,
    public_key       bytea NOT NULL,
    attestation_type varchar NOT NULL DEFAULT '',
    transports       text NOT NULL DEFAULT '[]',
    aaguid            bytea,
    sign_count        bigint NOT NULL DEFAULT 0 CONSTRAINT chk_auth_passkey_sign_count CHECK (sign_count >= 0),
    clone_warning     boolean NOT NULL DEFAULT false,
    user_present      boolean NOT NULL DEFAULT false,
    user_verified     boolean NOT NULL DEFAULT false,
    backup_eligible   boolean NOT NULL DEFAULT false,
    backup_state      boolean NOT NULL DEFAULT false,
    attachment        varchar NOT NULL DEFAULT '',
    last_used_at      timestamp with time zone,
    created           timestamp with time zone NOT NULL DEFAULT now(),
    updated           timestamp with time zone NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.auth_passkey_challenge
(
    token        varchar PRIMARY KEY,
    purpose      varchar NOT NULL CONSTRAINT chk_auth_passkey_challenge_purpose CHECK (purpose IN ('register', 'login')),
    user_id      bigint REFERENCES public.auth_user (id) ON DELETE CASCADE,
    session_data jsonb NOT NULL,
    expires      timestamp with time zone NOT NULL,
    created      timestamp with time zone NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_auth_passkey_credential_user_id
    ON public.auth_passkey_credential (user_id);
CREATE INDEX IF NOT EXISTS idx_auth_passkey_challenge_expires
    ON public.auth_passkey_challenge (expires);
