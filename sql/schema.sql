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
    secret        varchar,
    last_login_at timestamp with time zone,
    login_count   integer DEFAULT 0 CONSTRAINT chk_auth_user_login_count CHECK (login_count >= 0),
    avatar        varchar,
    is_verified   boolean DEFAULT false
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

-- Indexes
CREATE INDEX IF NOT EXISTS idx_auth_user_phone   ON public.auth_user (phone);
CREATE INDEX IF NOT EXISTS idx_auth_user_email   ON public.auth_user (email) WHERE email IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_auth_oauth2_authorization_code_client_id ON public.auth_oauth2_authorization_code (client_id);
CREATE INDEX IF NOT EXISTS idx_auth_oauth2_authorization_code_expires   ON public.auth_oauth2_authorization_code (expires);
CREATE INDEX IF NOT EXISTS idx_auth_oauth2_token_client_id              ON public.auth_oauth2_token (client_id);
CREATE INDEX IF NOT EXISTS idx_auth_oauth2_token_expires                ON public.auth_oauth2_token (expires);
CREATE INDEX IF NOT EXISTS idx_auth_oauth2_refresh_token_client_id      ON public.auth_oauth2_refresh_token (client_id);
CREATE INDEX IF NOT EXISTS idx_auth_oauth2_refresh_token_expires        ON public.auth_oauth2_refresh_token (expires);
CREATE INDEX IF NOT EXISTS idx_auth_oidc_jwk_kid                        ON public.auth_oidc_jwk (kid);

-- Ownership
ALTER TABLE public.auth_user                    OWNER TO postgres;
ALTER TABLE public.auth_oauth2_client           OWNER TO postgres;
ALTER TABLE public.auth_oauth2_authorization_code OWNER TO postgres;
ALTER TABLE public.auth_oauth2_token            OWNER TO postgres;
ALTER TABLE public.auth_oauth2_refresh_token    OWNER TO postgres;
ALTER TABLE public.auth_oidc_jwk                OWNER TO postgres;
