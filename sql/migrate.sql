-- 迁移脚本：将旧表名重命名为 auth_ 前缀版本。
-- 适用于已有旧表（user / oauth2_* / oidc_jwk）的存量数据库。
-- 如果已经是新表名则跳过，安全幂等。

DO $$
BEGIN
  -- user → auth_user
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name='user')
     AND NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name='auth_user')
  THEN
    ALTER TABLE public."user" RENAME TO auth_user;
    RAISE NOTICE 'Renamed: user → auth_user';
  END IF;

  -- oauth2_client → auth_oauth2_client
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name='oauth2_client')
     AND NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name='auth_oauth2_client')
  THEN
    ALTER TABLE public.oauth2_client RENAME TO auth_oauth2_client;
    RAISE NOTICE 'Renamed: oauth2_client → auth_oauth2_client';
  END IF;

  -- oauth2_authorization_code → auth_oauth2_authorization_code
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name='oauth2_authorization_code')
     AND NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name='auth_oauth2_authorization_code')
  THEN
    ALTER TABLE public.oauth2_authorization_code RENAME TO auth_oauth2_authorization_code;
    RAISE NOTICE 'Renamed: oauth2_authorization_code → auth_oauth2_authorization_code';
  END IF;

  -- oauth2_token → auth_oauth2_token
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name='oauth2_token')
     AND NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name='auth_oauth2_token')
  THEN
    ALTER TABLE public.oauth2_token RENAME TO auth_oauth2_token;
    RAISE NOTICE 'Renamed: oauth2_token → auth_oauth2_token';
  END IF;

  -- oauth2_refresh_token → auth_oauth2_refresh_token
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name='oauth2_refresh_token')
     AND NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name='auth_oauth2_refresh_token')
  THEN
    ALTER TABLE public.oauth2_refresh_token RENAME TO auth_oauth2_refresh_token;
    RAISE NOTICE 'Renamed: oauth2_refresh_token → auth_oauth2_refresh_token';
  END IF;

  -- oidc_jwk → auth_oidc_jwk
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name='oidc_jwk')
     AND NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name='auth_oidc_jwk')
  THEN
    ALTER TABLE public.oidc_jwk RENAME TO auth_oidc_jwk;
    RAISE NOTICE 'Renamed: oidc_jwk → auth_oidc_jwk';
  END IF;

  -- 为已有 auth_oidc_jwk 补齐 private_key 列（存 PEM 私钥，用于跨重启持久化 RSA 密钥对）
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name='auth_oidc_jwk')
     AND NOT EXISTS (
       SELECT 1 FROM information_schema.columns
       WHERE table_schema='public' AND table_name='auth_oidc_jwk' AND column_name='private_key'
     )
  THEN
    ALTER TABLE public.auth_oidc_jwk ADD COLUMN private_key text NOT NULL DEFAULT '';
    RAISE NOTICE 'Added column: auth_oidc_jwk.private_key';
  END IF;

  -- 为已有 auth_oauth2_authorization_code 补齐 PKCE 列
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name='auth_oauth2_authorization_code')
     AND NOT EXISTS (
       SELECT 1 FROM information_schema.columns
       WHERE table_schema='public' AND table_name='auth_oauth2_authorization_code' AND column_name='code_challenge'
     )
  THEN
    ALTER TABLE public.auth_oauth2_authorization_code ADD COLUMN code_challenge text;
    RAISE NOTICE 'Added column: auth_oauth2_authorization_code.code_challenge';
  END IF;

  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name='auth_oauth2_authorization_code')
     AND NOT EXISTS (
       SELECT 1 FROM information_schema.columns
       WHERE table_schema='public' AND table_name='auth_oauth2_authorization_code' AND column_name='code_challenge_method'
     )
  THEN
    ALTER TABLE public.auth_oauth2_authorization_code ADD COLUMN code_challenge_method varchar;
    RAISE NOTICE 'Added column: auth_oauth2_authorization_code.code_challenge_method';
  END IF;
END $$;
