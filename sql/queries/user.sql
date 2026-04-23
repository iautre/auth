-- name: UserById :one
SELECT id, phone, email, nickname, "group", enabled, created, updated, aid, secret, last_login_at, login_count, avatar, is_verified
FROM public.auth_user
WHERE id = $1;

-- name: UserByPhone :one
SELECT id, phone, email, nickname, "group", enabled, created, updated, aid, secret, last_login_at, login_count, avatar, is_verified
FROM public.auth_user
WHERE phone = $1;
