-- name: ListPasskeyCredentialsByUser :many
SELECT id, user_id, name, device_info, credential_id, public_key, attestation_type, transports, aaguid,
       sign_count, clone_warning, user_present, user_verified, backup_eligible,
       backup_state, attachment, last_used_at, created, updated
FROM public.auth_passkey_credential
WHERE user_id = $1
ORDER BY created;

-- name: DeletePasskeyCredentialByUser :execrows
DELETE FROM public.auth_passkey_credential
WHERE id = $1 AND user_id = $2;

-- name: CountPasskeyCredentialsByUser :one
SELECT count(*)
FROM public.auth_passkey_credential
WHERE user_id = $1;

-- name: GetPasskeyCredentialByID :one
SELECT id, user_id, name, device_info, credential_id, public_key, attestation_type, transports, aaguid,
       sign_count, clone_warning, user_present, user_verified, backup_eligible,
       backup_state, attachment, last_used_at, created, updated
FROM public.auth_passkey_credential
WHERE credential_id = $1;

-- name: CreatePasskeyCredential :one
INSERT INTO public.auth_passkey_credential (
    user_id, device_info, credential_id, public_key, attestation_type, transports, aaguid,
    sign_count, clone_warning, user_present, user_verified, backup_eligible,
    backup_state, attachment
) VALUES (
    $1, $2, $3, $4, $5, $6, $7,
    $8, $9, $10, $11, $12,
    $13, $14
)
RETURNING id, user_id, name, device_info, credential_id, public_key, attestation_type, transports, aaguid,
          sign_count, clone_warning, user_present, user_verified, backup_eligible,
          backup_state, attachment, last_used_at, created, updated;

-- name: UpdatePasskeyCredentialName :one
UPDATE public.auth_passkey_credential
SET name = $3, updated = NOW()
WHERE id = $1 AND user_id = $2
RETURNING id, user_id, name, device_info, credential_id, public_key, attestation_type, transports, aaguid,
          sign_count, clone_warning, user_present, user_verified, backup_eligible,
          backup_state, attachment, last_used_at, created, updated;

-- name: UpdatePasskeyCredentialAfterAssertion :execrows
UPDATE public.auth_passkey_credential
SET sign_count      = $3,
    clone_warning   = $4,
    user_present    = $5,
    user_verified   = $6,
    backup_eligible = $7,
    backup_state    = $8,
    last_used_at    = NOW(),
    updated         = NOW()
WHERE user_id = $1 AND credential_id = $2;

-- name: CreatePasskeyChallenge :exec
INSERT INTO public.auth_passkey_challenge (token, purpose, user_id, session_data, expires)
VALUES ($1, $2, $3, $4, $5);

-- name: ConsumePasskeyChallenge :one
DELETE FROM public.auth_passkey_challenge
WHERE token = $1 AND purpose = $2 AND expires > NOW()
RETURNING token, purpose, user_id, session_data, expires, created;

-- name: DeleteExpiredPasskeyChallenges :execrows
DELETE FROM public.auth_passkey_challenge
WHERE expires <= NOW();
