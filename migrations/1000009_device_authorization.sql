-- RFC 8628 设备授权（device flow）：给没有浏览器、没有回调地址的客户端
-- （CLI、SSH、容器、CI、对话中的 agent）一条可完成的授权路径。
--
-- 两个码各有分工，不能混用：
--   device_code：CLI 在自己那头轮询用的长期秘密，只存 sha256，不落明文；
--   user_code：   人看/人核对用的短码（XXXX-XXXX），明文存储，页面大号展示。
--
-- status 状态机：pending -> approved（用户点允许）-> consumed（换出 token）；
-- denied / expired 为终态。approved -> consumed 是原子的（WHERE status='approved'），
-- 保证一个 device_code 只能换出一套 token，防 device_code 被截获后重复铸币。
CREATE TABLE IF NOT EXISTS public.auth_oauth2_device_code
(
    device_code_hash varchar PRIMARY KEY,
    user_code        varchar NOT NULL,
    client_id        varchar NOT NULL,
    scope            text,
    resource         varchar,
    status           varchar NOT NULL DEFAULT 'pending',
    user_id          bigint,
    expires          timestamp with time zone NOT NULL,
    interval_seconds integer NOT NULL DEFAULT 5,
    last_polled      timestamp with time zone,
    created          timestamp with time zone NOT NULL DEFAULT now(),
    CONSTRAINT auth_oauth2_device_code_client_id_fkey
        FOREIGN KEY (client_id) REFERENCES public.auth_oauth2_client (id) ON DELETE CASCADE
);

-- 轮询按 device_code_hash 找；确认页按 user_code 找，都要能命中。
CREATE INDEX IF NOT EXISTS idx_auth_oauth2_device_code_user_code ON public.auth_oauth2_device_code (user_code);
CREATE INDEX IF NOT EXISTS idx_auth_oauth2_device_code_expires    ON public.auth_oauth2_device_code (expires);
