-- 1000001 baseline：auth 全部表结构基线。
-- auth 保留 1000001-1999999 迁移版本段，避免包内嵌时与宿主应用从 0001 开始的迁移冲突。
-- 全部 IF NOT EXISTS，对存量生产库（已建表）幂等无害；全新库则一次性建好。
-- 所有 auth 表使用 auth_ 前缀，避免嵌入其他服务时冲突。

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS public.auth_user
(
    id            bigserial PRIMARY KEY,
    phone         varchar,
    email         varchar,
    nickname      varchar,
    "group"       varchar,
    enabled       boolean NOT NULL DEFAULT true,
    created       timestamp with time zone NOT NULL DEFAULT now(),
    updated       timestamp with time zone NOT NULL DEFAULT now(),
    aid           varchar,
    secret        varchar,
    last_login_at timestamp with time zone,
    login_count   integer DEFAULT 0 CONSTRAINT chk_auth_user_login_count CHECK (login_count >= 0),
    avatar        varchar,
    is_verified   boolean DEFAULT false
);

CREATE TABLE IF NOT EXISTS public.auth_otp_credential
(
    id           bigserial PRIMARY KEY,
    user_id      bigint NOT NULL REFERENCES public.auth_user (id) ON DELETE CASCADE,
    name         varchar NOT NULL,
    secret       varchar NOT NULL,
    last_used_at timestamp with time zone,
    created      timestamp with time zone NOT NULL DEFAULT now(),
    updated      timestamp with time zone NOT NULL DEFAULT now(),
    UNIQUE (user_id, secret)
);

CREATE TABLE IF NOT EXISTS public.auth_otp_enrollment
(
    token   varchar PRIMARY KEY,
    user_id bigint NOT NULL REFERENCES public.auth_user (id) ON DELETE CASCADE,
    name    varchar NOT NULL,
    secret  varchar NOT NULL,
    expires timestamp with time zone NOT NULL,
    created timestamp with time zone NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.auth_oauth2_client
(
    id                varchar PRIMARY KEY,
    name              varchar NOT NULL,
    secret            varchar NOT NULL,
    redirect_uris     text NOT NULL,
    scopes            text NOT NULL,
    grant_types       text NOT NULL,
    access_token_ttl  bigint NOT NULL DEFAULT 3600,
    refresh_token_ttl bigint NOT NULL DEFAULT 2592000,
    enabled           boolean NOT NULL DEFAULT true,
    created           timestamp with time zone NOT NULL DEFAULT now(),
    updated           timestamp with time zone NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.auth_oauth2_authorization_code
(
    code                  varchar PRIMARY KEY,
    client_id             varchar NOT NULL,
    user_id               bigint NOT NULL,
    redirect_uri          text,
    scope                 text,
    state                 text,
    nonce                 text,
    code_challenge        text,
    code_challenge_method varchar,
    expires               timestamp with time zone NOT NULL,
    created               timestamp with time zone NOT NULL DEFAULT now(),
    CONSTRAINT auth_oauth2_authorization_code_client_id_fkey
        FOREIGN KEY (client_id) REFERENCES public.auth_oauth2_client (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS public.auth_oauth2_token
(
    access_token varchar PRIMARY KEY,
    token_type   text NOT NULL DEFAULT 'Bearer',
    client_id    varchar NOT NULL,
    user_id      bigint NOT NULL,
    scope        text,
    expires      timestamp with time zone NOT NULL,
    created      timestamp with time zone NOT NULL DEFAULT now(),
    CONSTRAINT auth_oauth2_token_client_id_fkey
        FOREIGN KEY (client_id) REFERENCES public.auth_oauth2_client (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS public.auth_oauth2_refresh_token
(
    refresh_token varchar PRIMARY KEY,
    client_id     varchar NOT NULL,
    user_id       bigint NOT NULL,
    scope         text,
    expires       timestamp with time zone NOT NULL,
    created       timestamp with time zone NOT NULL DEFAULT now(),
    CONSTRAINT auth_oauth2_refresh_token_client_id_fkey
        FOREIGN KEY (client_id) REFERENCES public.auth_oauth2_client (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS public.auth_oidc_jwk
(
    id          varchar PRIMARY KEY,
    kid         varchar NOT NULL UNIQUE,
    kty         varchar NOT NULL,
    use         varchar NOT NULL,
    alg         varchar NOT NULL,
    n           text NOT NULL,
    e           text NOT NULL,
    private_key text NOT NULL DEFAULT '',
    created     timestamp with time zone NOT NULL DEFAULT now(),
    updated     timestamp with time zone NOT NULL DEFAULT now()
);

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

CREATE INDEX IF NOT EXISTS idx_auth_user_phone   ON public.auth_user (phone);
CREATE INDEX IF NOT EXISTS idx_auth_user_email   ON public.auth_user (email) WHERE email IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_auth_user_phone ON public.auth_user (phone) WHERE phone IS NOT NULL AND btrim(phone) <> '';
CREATE UNIQUE INDEX IF NOT EXISTS uq_auth_user_email_lower ON public.auth_user (lower(email)) WHERE email IS NOT NULL AND btrim(email) <> '';
CREATE INDEX IF NOT EXISTS idx_auth_otp_credential_user_id ON public.auth_otp_credential (user_id);
CREATE INDEX IF NOT EXISTS idx_auth_otp_enrollment_expires ON public.auth_otp_enrollment (expires);
CREATE INDEX IF NOT EXISTS idx_auth_oauth2_authorization_code_client_id ON public.auth_oauth2_authorization_code (client_id);
CREATE INDEX IF NOT EXISTS idx_auth_oauth2_authorization_code_expires   ON public.auth_oauth2_authorization_code (expires);
CREATE INDEX IF NOT EXISTS idx_auth_oauth2_token_client_id              ON public.auth_oauth2_token (client_id);
CREATE INDEX IF NOT EXISTS idx_auth_oauth2_token_expires                ON public.auth_oauth2_token (expires);
CREATE INDEX IF NOT EXISTS idx_auth_oauth2_refresh_token_client_id      ON public.auth_oauth2_refresh_token (client_id);
CREATE INDEX IF NOT EXISTS idx_auth_oauth2_refresh_token_expires        ON public.auth_oauth2_refresh_token (expires);
CREATE INDEX IF NOT EXISTS idx_auth_oidc_jwk_kid                        ON public.auth_oidc_jwk (kid);
CREATE INDEX IF NOT EXISTS idx_auth_passkey_credential_user_id          ON public.auth_passkey_credential (user_id);
CREATE INDEX IF NOT EXISTS idx_auth_passkey_challenge_expires           ON public.auth_passkey_challenge (expires);
