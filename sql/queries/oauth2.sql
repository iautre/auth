-- name: CreateOAuth2Client :one
INSERT INTO public.auth_oauth2_client (id, name, secret, redirect_uris, scopes, grant_types, access_token_ttl, refresh_token_ttl, enabled, created, updated)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
RETURNING id, name, secret, redirect_uris, scopes, grant_types, access_token_ttl, refresh_token_ttl, enabled, created, updated;


-- name: GetOAuth2Client :one
SELECT id, name, secret, redirect_uris, scopes, grant_types, access_token_ttl, refresh_token_ttl, enabled, created, updated
FROM public.auth_oauth2_client
WHERE id = $1;

-- name: DisableOAuth2Client :exec
UPDATE public.auth_oauth2_client set enabled = false
WHERE id = $1;

-- name: UpdateOAuth2Client :one
-- 传空字符串/0 的列不变，仅覆盖显式指定的字段；enabled 仅在显式提供（非 NULL）时覆盖。
UPDATE public.auth_oauth2_client
SET name              = COALESCE(NULLIF(sqlc.arg(name)::varchar, ''), name),
    secret            = COALESCE(NULLIF(sqlc.arg(secret)::varchar, ''), secret),
    redirect_uris     = COALESCE(NULLIF(sqlc.arg(redirect_uris)::text, ''), redirect_uris),
    scopes            = COALESCE(NULLIF(sqlc.arg(scopes)::text, ''), scopes),
    grant_types       = COALESCE(NULLIF(sqlc.arg(grant_types)::text, ''), grant_types),
    access_token_ttl  = CASE WHEN sqlc.arg(access_token_ttl)::bigint > 0 THEN sqlc.arg(access_token_ttl)::bigint ELSE access_token_ttl END,
    refresh_token_ttl = CASE WHEN sqlc.arg(refresh_token_ttl)::bigint > 0 THEN sqlc.arg(refresh_token_ttl)::bigint ELSE refresh_token_ttl END,
    enabled           = COALESCE(sqlc.narg(enabled)::boolean, enabled),
    updated           = NOW()
WHERE id = sqlc.arg(id)
RETURNING id, name, secret, redirect_uris, scopes, grant_types, access_token_ttl, refresh_token_ttl, enabled, created, updated;

-- name: UpdateOAuth2ClientSecret :one
UPDATE public.auth_oauth2_client
SET secret  = $2,
    updated = NOW()
WHERE id = $1
RETURNING id, name, secret, redirect_uris, scopes, grant_types, access_token_ttl, refresh_token_ttl, enabled, created, updated;

-- name: ListOAuth2Client :many
SELECT id, name, secret, redirect_uris, scopes, grant_types, access_token_ttl, refresh_token_ttl, enabled, created, updated
FROM public.auth_oauth2_client;

-- name: CreateOAuth2AuthorizationCode :one
INSERT INTO public.auth_oauth2_authorization_code (code, client_id, user_id, redirect_uri, scope, state, nonce, code_challenge, code_challenge_method, expires, created)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())
RETURNING code, client_id, user_id, redirect_uri, scope, state, nonce, code_challenge, code_challenge_method, expires, created;

-- name: GetOAuth2AuthorizationCode :one
SELECT code, client_id, user_id, redirect_uri, scope, state, nonce, code_challenge, code_challenge_method, expires, created
FROM public.auth_oauth2_authorization_code
WHERE code = $1 AND expires > NOW();

-- name: ConsumeOAuth2AuthorizationCode :one
DELETE FROM public.auth_oauth2_authorization_code
WHERE code = $1 AND client_id = $2 AND expires > NOW()
RETURNING code, client_id, user_id, redirect_uri, scope, state, nonce, code_challenge, code_challenge_method, expires, created;

-- name: CleanupExpiredAuthorizationCodes :exec
DELETE FROM public.auth_oauth2_authorization_code WHERE expires <= NOW();

-- name: CreateOAuth2Token :one
INSERT INTO public.auth_oauth2_token (access_token, token_type, client_id, user_id, scope, expires, created)
VALUES ($1, $2, $3, $4, $5, $6, NOW())
RETURNING access_token, token_type, client_id, user_id, scope, expires, created;

-- name: GetOAuth2Token :one
SELECT access_token, token_type, client_id, user_id, scope, expires, created
FROM public.auth_oauth2_token
WHERE access_token = $1 AND expires > NOW();

-- name: GetOAuth2TokensByUser :many
SELECT access_token, token_type, client_id, user_id, scope, expires, created
FROM public.auth_oauth2_token
WHERE user_id = $1 AND expires > NOW()
ORDER BY created DESC;

-- name: RevokeOAuth2Token :exec
DELETE FROM public.auth_oauth2_token WHERE access_token = $1;

-- name: RevokeOAuth2TokensByUser :exec
DELETE FROM public.auth_oauth2_token WHERE user_id = $1;

-- name: CleanupExpiredTokens :exec
DELETE FROM public.auth_oauth2_token WHERE expires <= NOW();

-- name: CreateOAuth2RefreshToken :one
INSERT INTO public.auth_oauth2_refresh_token (refresh_token, client_id, user_id, scope, expires, created)
VALUES ($1, $2, $3, $4, $5, NOW())
RETURNING refresh_token, client_id, user_id, scope, expires, created;

-- name: GetOAuth2RefreshToken :one
SELECT refresh_token, client_id, user_id, scope, expires, created
FROM public.auth_oauth2_refresh_token
WHERE refresh_token = $1 AND expires > NOW();

-- name: GetOAuth2RefreshTokensByUser :many
SELECT refresh_token, client_id, user_id, scope, expires, created
FROM public.auth_oauth2_refresh_token
WHERE user_id = $1 AND expires > NOW()
ORDER BY created DESC;

-- name: RevokeOAuth2RefreshToken :exec
DELETE FROM public.auth_oauth2_refresh_token WHERE refresh_token = $1;

-- name: RevokeOAuth2RefreshTokensByUser :exec
DELETE FROM public.auth_oauth2_refresh_token WHERE user_id = $1;

-- name: CleanupExpiredRefreshTokens :exec
DELETE FROM public.auth_oauth2_refresh_token WHERE expires <= NOW();

-- name: GetOAuth2ClientStats :one
SELECT
    c.id,
    c.name,
    COUNT(DISTINCT ac.code) as auth_codes_count,
    COUNT(DISTINCT t.access_token) as active_tokens_count,
    COUNT(DISTINCT rt.refresh_token) as active_refresh_tokens_count
FROM public.auth_oauth2_client c
LEFT JOIN public.auth_oauth2_authorization_code ac ON c.id = ac.client_id
LEFT JOIN public.auth_oauth2_token t ON c.id = t.client_id AND t.expires > NOW()
LEFT JOIN public.auth_oauth2_refresh_token rt ON c.id = rt.client_id AND rt.expires > NOW()
WHERE c.id = $1
GROUP BY c.id, c.name;

-- name: GetOIDCJwk :one
SELECT id, kid, kty, use, alg, n, e, private_key, created, updated
FROM public.auth_oidc_jwk
WHERE kid = $1;

-- name: ListOIDCJwks :many
SELECT id, kid, kty, use, alg, n, e, private_key, created, updated
FROM public.auth_oidc_jwk
ORDER BY created DESC;

-- name: GetActiveOIDCJwks :many
SELECT id, kid, kty, use, alg, n, e, private_key, created, updated
FROM public.auth_oidc_jwk
ORDER BY created DESC;

-- name: GetLatestOIDCJwk :one
SELECT id, kid, kty, use, alg, n, e, private_key, created, updated
FROM public.auth_oidc_jwk
ORDER BY created DESC
LIMIT 1;

-- name: CreateOIDCJwk :one
INSERT INTO public.auth_oidc_jwk (id, kid, kty, use, alg, n, e, private_key)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING id, kid, kty, use, alg, n, e, private_key, created, updated;
