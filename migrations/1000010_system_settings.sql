-- 系统级设置：管理页面可读写的键值对。
-- 目前只承载注册开关（registration_open）；没有记录时回退 AUTH_AUTO_REGISTER，
-- 保证老部署升级后行为不变。
CREATE TABLE IF NOT EXISTS public.auth_system_setting
(
    key     varchar(64) PRIMARY KEY,
    value   text        NOT NULL,
    updated timestamp with time zone NOT NULL DEFAULT now()
);
