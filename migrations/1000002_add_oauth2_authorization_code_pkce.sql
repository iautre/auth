ALTER TABLE public.auth_oauth2_authorization_code
    ADD COLUMN IF NOT EXISTS code_challenge text,
    ADD COLUMN IF NOT EXISTS code_challenge_method varchar;
