ALTER TABLE public.auth_oidc_jwk
    ADD COLUMN IF NOT EXISTS private_key text NOT NULL DEFAULT '';
