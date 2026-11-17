-- Database Schema for SQLC（仅用于全新数据库初始化）
-- 已有旧表（user / oauth2_* / oidc_jwk）的存量数据库请执行 migrate.sql 重命名，不要重新建表。
-- All auth tables use the auth_ prefix to avoid conflicts when embedded in other services.

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- User Table
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

-- OAuth2 Clients Table
CREATE TABLE IF NOT EXISTS public.auth_oauth2_client
(
    id               varchar PRIMARY KEY,
    name             varchar NOT NULL,
    secret           varchar NOT NULL,
    redirect_uris    text NOT NULL,
    scopes           text NOT NULL,
    grant_types      text NOT NULL,
    access_token_ttl  bigint NOT NULL DEFAULT 3600,
    refresh_token_ttl bigint NOT NULL DEFAULT 2592000,
    enabled          boolean NOT NULL DEFAULT true,
    created          timestamp with time zone NOT NULL DEFAULT now(),
    updated          timestamp with time zone NOT NULL DEFAULT now()
);

-- OAuth2 Authorization Codes Table
-- code_challenge / code_challenge_method 用于 PKCE（RFC 7636），public client 必填，confidential client 可选。
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

-- OAuth2 Access Tokens Table
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

-- OAuth2 Refresh Tokens Table
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

-- OIDC JWK Keys Table
-- private_key 存储 PKCS#1 PEM 私钥，用于服务端签名；对外 /oidc/jwks 仅暴露 n/e。
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

-- WebAuthn discoverable credentials used by Passkey login.
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

-- WebAuthn ceremonies are server-side, short-lived and single-use.
CREATE TABLE IF NOT EXISTS public.auth_passkey_challenge
(
    token        varchar PRIMARY KEY,
    purpose      varchar NOT NULL CONSTRAINT chk_auth_passkey_challenge_purpose CHECK (purpose IN ('register', 'login')),
    user_id      bigint REFERENCES public.auth_user (id) ON DELETE CASCADE,
    session_data jsonb NOT NULL,
    expires      timestamp with time zone NOT NULL,
    created      timestamp with time zone NOT NULL DEFAULT now()
);

-- One-time verification codes for SMS / email
CREATE TABLE IF NOT EXISTS public.auth_verification_code
(
    id          bigserial PRIMARY KEY,
    channel     varchar                  NOT NULL,
    target      varchar                  NOT NULL,
    purpose     varchar                  NOT NULL,
    code_hash   varchar                  NOT NULL,
    attempts    integer                  NOT NULL DEFAULT 0,
    expires     timestamp with time zone NOT NULL,
    consumed_at timestamp with time zone,
    created     timestamp with time zone NOT NULL DEFAULT now(),
    CONSTRAINT chk_auth_verification_channel CHECK (channel IN ('sms', 'email')),
    CONSTRAINT chk_auth_verification_purpose CHECK (purpose IN ('login', 'register', 'verify_email', 'verify_phone')),
    CONSTRAINT chk_auth_verification_attempts CHECK (attempts >= 0)
);

-- Third-party identity binding (auth as OIDC relying party)
CREATE TABLE IF NOT EXISTS public.auth_identity
(
    id             bigserial PRIMARY KEY,
    user_id        bigint                   NOT NULL REFERENCES public.auth_user (id) ON DELETE CASCADE,
    provider       varchar                  NOT NULL,
    issuer         varchar                  NOT NULL,
    subject        varchar                  NOT NULL,
    email          varchar,
    email_verified boolean                  NOT NULL DEFAULT false,
    display_name   varchar,
    avatar         varchar,
    created        timestamp with time zone NOT NULL DEFAULT now(),
    updated        timestamp with time zone NOT NULL DEFAULT now(),
    UNIQUE (provider, subject)
);

-- Federated login session (state / nonce / PKCE verifier)
CREATE TABLE IF NOT EXISTS public.auth_federated_session
(
    state_hash    varchar PRIMARY KEY,
    provider      varchar                  NOT NULL,
    nonce         varchar                  NOT NULL,
    code_verifier varchar                  NOT NULL,
    return_to     varchar,
    expires       timestamp with time zone NOT NULL,
    created       timestamp with time zone NOT NULL DEFAULT now()
);

-- Third-party OIDC provider configuration (managed from the admin page)
CREATE TABLE IF NOT EXISTS public.auth_identity_provider
(
    id            bigserial PRIMARY KEY,
    name          varchar                  NOT NULL UNIQUE,
    label         varchar                  NOT NULL,
    issuer        varchar                  NOT NULL,
    client_id     varchar                  NOT NULL,
    client_secret varchar                  NOT NULL,
    scopes        varchar                  NOT NULL DEFAULT 'openid email profile',
    auto_register boolean                  NOT NULL DEFAULT true,
    enabled       boolean                  NOT NULL DEFAULT true,
    created       timestamp with time zone NOT NULL DEFAULT now(),
    updated       timestamp with time zone NOT NULL DEFAULT now(),
    CONSTRAINT chk_auth_identity_provider_name CHECK (name ~ '^[a-z0-9_-]{2,32}$')
);

-- Indexes
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
CREATE INDEX IF NOT EXISTS idx_auth_verification_lookup                 ON public.auth_verification_code (channel, target, purpose, created DESC);
CREATE INDEX IF NOT EXISTS idx_auth_verification_expires                ON public.auth_verification_code (expires);
CREATE INDEX IF NOT EXISTS idx_auth_identity_user_id                    ON public.auth_identity (user_id);
CREATE INDEX IF NOT EXISTS idx_auth_federated_session_expires           ON public.auth_federated_session (expires);

-- Ownership
ALTER TABLE public.auth_user                    OWNER TO postgres;
ALTER TABLE public.auth_otp_credential          OWNER TO postgres;
ALTER TABLE public.auth_otp_enrollment          OWNER TO postgres;
ALTER TABLE public.auth_oauth2_client           OWNER TO postgres;
ALTER TABLE public.auth_oauth2_authorization_code OWNER TO postgres;
ALTER TABLE public.auth_oauth2_token            OWNER TO postgres;
ALTER TABLE public.auth_oauth2_refresh_token    OWNER TO postgres;
ALTER TABLE public.auth_oidc_jwk                OWNER TO postgres;
ALTER TABLE public.auth_passkey_credential      OWNER TO postgres;
ALTER TABLE public.auth_passkey_challenge       OWNER TO postgres;
ALTER TABLE public.auth_verification_code       OWNER TO postgres;
ALTER TABLE public.auth_identity                OWNER TO postgres;
ALTER TABLE public.auth_federated_session       OWNER TO postgres;
ALTER TABLE public.auth_identity_provider       OWNER TO postgres;
