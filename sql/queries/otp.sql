-- name: ListOtpCredentialsByUser :many
SELECT id, user_id, name, last_used_at, created, updated
FROM public.auth_otp_credential
WHERE user_id = $1
ORDER BY created;

-- name: ListOtpSecretsByUser :many
SELECT id, secret
FROM public.auth_otp_credential
WHERE user_id = $1
ORDER BY created;

-- name: CreateOtpCredential :one
INSERT INTO public.auth_otp_credential (user_id, name, secret)
VALUES ($1, $2, $3)
RETURNING id, user_id, name, secret, last_used_at, created, updated;

-- name: UpdateOtpCredentialAfterLogin :execrows
UPDATE public.auth_otp_credential
SET last_used_at = NOW(), updated = NOW()
WHERE id = $1 AND user_id = $2;

-- name: CountOtpCredentialsByUser :one
SELECT count(*)
FROM public.auth_otp_credential
WHERE user_id = $1;

-- name: DeleteOtpCredentialByUser :execrows
DELETE FROM public.auth_otp_credential
WHERE id = $1 AND user_id = $2;

-- name: DeleteAllOtpCredentialsByUser :execrows
DELETE FROM public.auth_otp_credential
WHERE user_id = $1;

-- name: CreateOtpEnrollment :exec
INSERT INTO public.auth_otp_enrollment (token, user_id, name, secret, expires)
VALUES ($1, $2, $3, $4, $5);

-- name: GetOtpEnrollment :one
SELECT token, user_id, name, secret, expires, created
FROM public.auth_otp_enrollment
WHERE token = $1 AND user_id = $2 AND expires > NOW();

-- name: ConsumeOtpEnrollment :execrows
DELETE FROM public.auth_otp_enrollment
WHERE token = $1 AND user_id = $2 AND expires > NOW();

-- name: DeleteExpiredOtpEnrollments :execrows
DELETE FROM public.auth_otp_enrollment
WHERE expires <= NOW();
