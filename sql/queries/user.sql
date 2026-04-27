-- name: UserById :one
SELECT id, phone, email, nickname, "group", enabled, created, updated, aid, secret, last_login_at, login_count, avatar, is_verified
FROM public.auth_user
WHERE id = $1;

-- name: UserByPhone :one
SELECT id, phone, email, nickname, "group", enabled, created, updated, aid, secret, last_login_at, login_count, avatar, is_verified
FROM public.auth_user
WHERE phone = $1;

-- name: UpdateUserLoginInfo :exec
UPDATE public.auth_user
SET last_login_at = NOW(),
    login_count   = COALESCE(login_count, 0) + 1,
    updated       = NOW()
WHERE id = $1;

-- name: UpdateUserSecret :exec
UPDATE public.auth_user
SET secret  = $2,
    updated = NOW()
WHERE id = $1;
