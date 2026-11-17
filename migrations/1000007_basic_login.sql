-- 1000007 passwordless login：一次性验证码、第三方身份绑定、联邦登录会话、provider 配置。
-- 全部 IF NOT EXISTS，对存量库幂等。
-- 不引入密码：登录方式只有 OTP、通行密钥、一次性验证码与第三方 OIDC。

-- 一次性验证码：短信与邮件共用，只存摘要，不存明文。
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

CREATE INDEX IF NOT EXISTS idx_auth_verification_lookup
    ON public.auth_verification_code (channel, target, purpose, created DESC);

CREATE INDEX IF NOT EXISTS idx_auth_verification_expires
    ON public.auth_verification_code (expires);

-- 第三方身份绑定：provider 存 auth_identity_provider.name（创建后不可改名）。
-- 同一用户可以绑定多个 provider，UNIQUE(provider, subject) 保证一个外部身份只对应一个本地用户。
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

CREATE INDEX IF NOT EXISTS idx_auth_identity_user_id ON public.auth_identity (user_id);

-- 联邦登录会话：state 只存摘要，落库而非内存，保证包被多实例部署时也能回调。
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

CREATE INDEX IF NOT EXISTS idx_auth_federated_session_expires
    ON public.auth_federated_session (expires);

-- 第三方 provider 配置：独立部署走管理中心页面维护，包形态由宿主调管理 API 或 seed。
-- client_secret 落库前用 AUTH_ENCRYPTION_KEY 加密，不存明文。
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
