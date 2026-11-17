-- RFC 8707 资源指示：access token 绑定 audience。
--
-- 授权请求里带 resource，随授权码传到 token 端点，签发时写入 audience；
-- refresh token 也要记住，否则刷新出来的新 token 会丢掉 audience，
-- 多服务共用一套 auth 时隔离性会被一次刷新抹平。
ALTER TABLE public.auth_oauth2_authorization_code
    ADD COLUMN IF NOT EXISTS resource varchar;

ALTER TABLE public.auth_oauth2_token
    ADD COLUMN IF NOT EXISTS audience varchar;

ALTER TABLE public.auth_oauth2_refresh_token
    ADD COLUMN IF NOT EXISTS audience varchar;
