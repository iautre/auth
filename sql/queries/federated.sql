-- name: InsertFederatedSession :exec
INSERT INTO public.auth_federated_session (state_hash, provider, nonce, code_verifier, return_to, expires)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: FederatedSessionByState :one
SELECT state_hash, provider, nonce, code_verifier, return_to, expires, created
FROM public.auth_federated_session
WHERE state_hash = $1;

-- name: DeleteFederatedSession :exec
DELETE
FROM public.auth_federated_session
WHERE state_hash = $1;

-- name: DeleteExpiredFederatedSessions :exec
DELETE
FROM public.auth_federated_session
WHERE expires < NOW();
