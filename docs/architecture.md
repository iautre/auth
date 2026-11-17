# auth 架构与授权流程原理

auth（`github.com/iautre/auth`）一个模块干三件事：**发 token（授权服务器）、管账号（身份提供方）、被引用（可嵌入库）**。

## 一、整体架构

```
┌─────────────────────────────────────────────────────────────────┐
│                     auth（github.com/iautre/auth）              │
│          授权服务器 + 身份提供方 + 可嵌入库，三合一               │
├───────────────────────────────┬─────────────────────────────────┤
│ 授权服务器（OAuth2/OIDC）      │ 身份提供方（IdP / 账号体系）     │
│  /oauth2/authorize            │  登录：验证码 / OTP / 通行密钥   │
│  /oauth2/token                │  第三方 OIDC 登录 /federated/*  │
│  /oauth2/device_authorization │  账号中心 /account、个人资料     │
│  /oauth2/register (RFC7591)   │  管理员 /admin/providers 配 IdP  │
│  /oauth2/introspect · /revoke │  MQTT 设备鉴权 /mqtt/auth        │
│  /.well-known/openid-config   │  身份绑定 /identities            │
│  /.well-known/oauth-protected │                                 │
│  /oidc/userinfo · /oidc/jwks  │                                 │
├───────────────────────────────┴─────────────────────────────────┤
│ 持久层：PostgreSQL（15 张 auth_* 表）+ Redis（token 缓存、会话）  │
├─────────────────────────────────────────────────────────────────┤
│ 对外导出 pkg/authhttp：Setup / MountAPI / MountOAuth /           │
│ MountFederated · MCPAuth · ValidateAccessToken                   │
└─────────────────────────────────────────────────────────────────┘
```

三个角色：

1. **授权服务器**：给第三方客户端发 token，实现 OAuth2 / OIDC 协议端点。
2. **身份提供方**：管用户账号和登录方式（验证码、OTP、通行密钥、第三方 OIDC）。
3. **可嵌入库**：别的进程把它当模块挂进去，开关控制挂哪些端点。

## 二、授权码流程（authorization_code）

给有浏览器的 Web 应用。核心是「code 走浏览器、token 走后端」，PKCE 防 code 被截。

```
客户端              浏览器/用户              auth 授权服务器
  │                     │                        │
  │ 1. 发起授权请求 ────▶│                        │
  │   (client_id, redirect_uri, scope, state, code_challenge)
  │                     │ 2. 跳转 /oauth2/authorize（未登录先去登录页）
  │                     │───────────────────────▶│
  │                     │ 3. 用户登录并确认授权（consent 页）
  │                     │───────────────────────▶│
  │                     │◀──── 4. 302 redirect_uri?code&state ────│
  │◀── 5. 把 code 交给客户端 ──│                        │
  │ 6. POST /oauth2/token (code + code_verifier + client 凭据) ──▶│
  │◀── 7. 校验 PKCE + code 一次性，返回 access + refresh + id_token │
  │ 8. 携带 access_token 调用资源 ─────────────────────▶│
  │ 9. 资源方可选 /oauth2/introspect 校验 ─────────────▶│
  │ 10. 过期后用 refresh_token 换新 ───────────────────▶│
```

## 三、设备授权流程（device flow，RFC 8628）

给没有浏览器、没有回调地址的客户端（CLI、SSH、对话里的 agent）。这是本次核心。

核心设计：

- **device_code 走轮询换 token（秘密）**，**user_code 走 URL 给用户看（人读）**，两条线解耦。
- device_code 只存 sha256，明文不进库、不进 URL。
- 一次性消费：`UPDATE ... WHERE status='approved'` 原子转换，杜绝重复铸币。
- 失效页统一：已用 / 已拒 / 过期 / 不存在，全回「链接已失效」，连 client 名都不查。

```
客户端(CLI/agent)      浏览器/用户           auth 授权服务器
  │                       │                      │
  │ 1. POST /oauth2/device_authorization (client_id, scope) ──▶│
  │◀── 2. 返回 device_code + user_code + verification_uri + interval │
  │      (device_code 只存 sha256)
  │ 3. 把 verification_uri?user_code=XXXX-XXXX 给用户 ──▶│
  │                       │ 4. 打开链接，/device 页大号展示 user_code
  │                       │────────────────────▶│
  │                       │ 5. 点「允许」，原子 pending → approved
  │                       │────────────────────▶│
  │ 6. 轮询 POST /oauth2/device_poll (device_code) ──▶│
  │◀── 7. 未批准 authorization_pending；轮太勤 slow_down │
  │◀── 8. 批准后返回 access_token + refresh_token │
  │ 9. device_code 原子 approved → consumed，只能换一次 ──▶│
  │                       │ 10. 再访问 /device → 统一「链接已失效」
  │                       │────────────────────▶│
```

user_code 是 8 位免混淆码（`XXXX-XXXX`），字符集去掉 0O1IL。

## 四、MCP 授权认证闭环（RFC 9728 + RFC 8628）

第三方 MCP 客户端（cursor / hermes 等）连上 `/mcp` 后，如何发现授权服务器并完成授权。

```
MCP 客户端          宿主进程 /mcp           auth 授权服务器
  │                     │                      │
  │ 1. 直连 /mcp，没带 token ──▶│                │
  │◀── 2. 401 + WWW-Authenticate: resource_metadata=... │
  │ 3. 读 /.well-known/oauth-protected-resource/mcp ──▶│
  │◀── 4. authorization_servers + scopes_supported │
  │ 5. 对授权服务器走 device flow 换 token ──▶│
  │◀── 6. 用户浏览器确认，拿到 access_token │
  │ 7. 带 Bearer access_token 再调 /mcp ──▶│                │
  │                     │ 8. MCPAuth 调 ValidateAccessToken（查 token 表）
  │                     │────────────────────▶│
  │                     │◀── 9. 通过，写用户上下文，工具执行 │
```

关键前提（对应「OAuth: false 没法做 MCP 授权」的本质）：

- `OAuth: true` + `DeviceFlow: true` 才挂授权端点。
- `ProtectedResourcePath: /mcp` 才发 `/.well-known/oauth-protected-resource` 元数据。
- `MCPAuth` 只负责验 token，授权服务器可以是本进程，也可以是别处（`authorization_servers` 指向）。
- token 校验和「谁是授权服务器」是解耦的：`OAuth: false` 只是关掉了「本进程当授权服务器」，`ValidateAccessToken` 始终能用。

## 五、数据表关系（15 张，均带 auth_ 前缀）

分四个域：

| 域 | 表 | 说明 |
|---|---|---|
| 用户域 | `auth_user` | 用户主表 |
| | `auth_otp_credential` | OTP 验证器（一个用户多个） |
| | `auth_otp_enrollment` | OTP 绑定进行中 |
| | `auth_passkey_credential` | 通行密钥 |
| | `auth_passkey_challenge` | WebAuthn 流程 |
| OAuth2 授权域 | `auth_oauth2_client` | OAuth2 客户端 |
| | `auth_oauth2_authorization_code` | 授权码（PKCE + resource） |
| | `auth_oauth2_token` | access token（audience） |
| | `auth_oauth2_refresh_token` | refresh token（audience） |
| | `auth_oauth2_device_code` | 设备授权（RFC 8628） |
| 联邦登录域 | `auth_identity_provider` | 第三方 IdP 配置（admin 管理） |
| | `auth_identity` | 用户-IdP 绑定 |
| | `auth_federated_session` | 登录会话 state/nonce/verifier |
| 验证码 | `auth_verification_code` | 短信/邮箱一次性验证码 |
| 密钥 | `auth_oidc_jwk` | OIDC 签名私钥（只暴露 n/e） |

外键关系：

- `user_id → auth_user(id)`：otp_credential、otp_enrollment、passkey_credential、identity、authorization_code、token、refresh_token（device_code 的 user_id 也指向 user，但允许为空，待批准）。
- `client_id → auth_oauth2_client(id)`：authorization_code、token、refresh_token、device_code。
- `oidc_jwk` 无外键，独立存签名私钥。

状态机（设备授权）：`pending → approved → consumed`。

## 六、安全要点

1. **PKCE**：public client 必填 code_challenge，换 token 时验 code_verifier。
2. **device_code 存哈希**：明文不进库、不进 URL，泄露库也不等于泄露 code。
3. **一次性消费**：code / device_code 换 token 都用原子 UPDATE 状态转换，防重放。
4. **audience（RFC 8707）**：token 绑定资源，校验方不匹配回 `invalid_target`。
5. **失效页不泄密**：已用/已拒/过期统一「链接已失效」，不查 client 名。
6. **MCPAuth 拒绝无用户 token**：client_credentials 签发的 token 无 user_id，直接拒绝。
