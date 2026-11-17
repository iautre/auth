-- name: IdentityByProviderSubject :one
SELECT id, user_id, provider, issuer, subject, email, email_verified, display_name, avatar, created, updated
FROM public.auth_identity
WHERE provider = $1
  AND subject = $2;

-- name: IdentitiesByUser :many
SELECT id, user_id, provider, issuer, subject, email, email_verified, display_name, avatar, created, updated
FROM public.auth_identity
WHERE user_id = $1
ORDER BY created;

-- name: InsertIdentity :one
INSERT INTO public.auth_identity (user_id, provider, issuer, subject, email, email_verified, display_name, avatar)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING id, user_id, provider, issuer, subject, email, email_verified, display_name, avatar, created, updated;

-- name: DeleteIdentityByUserProvider :execrows
DELETE
FROM public.auth_identity
WHERE user_id = $1
  AND provider = $2;

-- name: CountIdentitiesByUser :one
SELECT COUNT(*)
FROM public.auth_identity
WHERE user_id = $1;

-- name: CountIdentitiesByProvider :one
SELECT COUNT(*)
FROM public.auth_identity
WHERE provider = $1;
