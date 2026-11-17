-- name: ListIdentityProviders :many
-- 管理用：含加密后的 client_secret，handler 输出前必须剥离。
SELECT id, name, label, issuer, client_id, client_secret, scopes, auto_register, enabled, created, updated
FROM public.auth_identity_provider
ORDER BY id;

-- name: ListPublicIdentityProviders :many
-- 登录页 / 前端渲染按钮用：不含任何密钥。
SELECT name, label
FROM public.auth_identity_provider
WHERE enabled
ORDER BY id;

-- name: IdentityProviderByName :one
SELECT id, name, label, issuer, client_id, client_secret, scopes, auto_register, enabled, created, updated
FROM public.auth_identity_provider
WHERE name = $1;

-- name: IdentityProviderById :one
SELECT id, name, label, issuer, client_id, client_secret, scopes, auto_register, enabled, created, updated
FROM public.auth_identity_provider
WHERE id = $1;

-- name: CreateIdentityProvider :one
INSERT INTO public.auth_identity_provider (name, label, issuer, client_id, client_secret, scopes, auto_register, enabled)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING id, name, label, issuer, client_id, client_secret, scopes, auto_register, enabled, created, updated;

-- name: UpdateIdentityProvider :one
UPDATE public.auth_identity_provider
SET label         = $2,
    issuer        = $3,
    client_id     = $4,
    client_secret = $5,
    scopes        = $6,
    auto_register = $7,
    enabled       = $8,
    updated       = NOW()
WHERE id = $1
RETURNING id, name, label, issuer, client_id, client_secret, scopes, auto_register, enabled, created, updated;

-- name: DeleteIdentityProvider :execrows
DELETE
FROM public.auth_identity_provider
WHERE id = $1;
