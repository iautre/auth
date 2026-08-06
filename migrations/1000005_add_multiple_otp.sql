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

INSERT INTO public.auth_otp_credential (user_id, name, secret)
SELECT id, '原有 OTP', secret
FROM public.auth_user
WHERE secret IS NOT NULL AND btrim(secret) <> ''
ON CONFLICT (user_id, secret) DO NOTHING;

ALTER TABLE public.auth_user DROP COLUMN IF EXISTS secret;

CREATE UNIQUE INDEX IF NOT EXISTS uq_auth_user_phone
    ON public.auth_user (phone)
    WHERE phone IS NOT NULL AND btrim(phone) <> '';
CREATE UNIQUE INDEX IF NOT EXISTS uq_auth_user_email_lower
    ON public.auth_user (lower(email))
    WHERE email IS NOT NULL AND btrim(email) <> '';
CREATE INDEX IF NOT EXISTS idx_auth_otp_credential_user_id
    ON public.auth_otp_credential (user_id);
CREATE INDEX IF NOT EXISTS idx_auth_otp_enrollment_expires
    ON public.auth_otp_enrollment (expires);
