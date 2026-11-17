-- name: InsertVerificationCode :one
INSERT INTO public.auth_verification_code (channel, target, purpose, code_hash, expires)
VALUES ($1, $2, $3, $4, $5)
RETURNING id, channel, target, purpose, code_hash, attempts, expires, consumed_at, created;

-- name: LatestVerificationCode :one
SELECT id, channel, target, purpose, code_hash, attempts, expires, consumed_at, created
FROM public.auth_verification_code
WHERE channel = $1
  AND target = $2
  AND purpose = $3
  AND consumed_at IS NULL
ORDER BY created DESC
LIMIT 1;

-- name: ConsumeVerificationCode :execrows
-- 并发安全的消费：只有仍未消费时才会受影响，返回 0 表示被别人抢先消费。
UPDATE public.auth_verification_code
SET consumed_at = NOW()
WHERE id = $1
  AND consumed_at IS NULL;

-- name: IncrementVerificationAttempts :exec
UPDATE public.auth_verification_code
SET attempts = attempts + 1
WHERE id = $1;

-- name: CountVerificationCodesSince :one
SELECT COUNT(*)
FROM public.auth_verification_code
WHERE channel = $1
  AND target = $2
  AND purpose = $3
  AND created > $4;

-- name: CountVerificationCodesByTargetSince :one
SELECT COUNT(*)
FROM public.auth_verification_code
WHERE target = $1
  AND created > $2;

-- name: DeleteExpiredVerificationCodes :exec
DELETE
FROM public.auth_verification_code
WHERE expires < NOW();
