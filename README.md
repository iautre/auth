# Auth

用 Go 写的 OIDC 授权服务器，同时可以作为库被其他 Go 服务直接引用。登录方式有邮箱验证码（无密码）、Passkey、TOTP 验证器，以及第三方 OIDC 联邦登录（Google / GitLab / Keycloak 等）。因为对外就是标准 OAuth2/OIDC，它也可以直接给 MCP 客户端当授权服务器用。

同一套表结构、同一套类型支持两种形态：

- **独立部署**：跑起来就是一个完整的登录站点，带内置登录页和账号中心。
- **当包用**：`authhttp.Setup()` 挂到宿主的 gin 引擎上，宿主复用它的登录能力和鉴权中间件。

## 独立部署

需要 PostgreSQL。没有配置 `DATABASE_DSN`（或 `DATABASE_ENABLED=false`）时进程会直接拒绝启动——这个项目里所有数据都依赖它。

```bash
make build && ./bin/server   # 环境变量从 shell 继承
make deploy                  # 构建 linux/amd64 镜像 → 推 cnb → 服务器拉取重启
```

`make deploy` 需要 `.env` 里的 `DEPLOY_HOST`（`user@host`）；Makefile 会自动 include 同目录的 `.env`。服务器上敏感项（`AUTH_ENCRYPTION_KEY`、`AUTH_SMTP_*`）走 `--env-file /app/docker/auth/auth.env` 注入，不走命令行——`docker --env-file` 逐行读取、不做变量展开，密码里的 `$` 等字符能原样保留。

表结构由进程启动时自动迁移，不需要手工执行 SQL。第一个注册的账号会自动成为管理员（库内没有管理员时提权，靠 advisory lock 保证并发安全），所以**部署完先把自己的账号注册掉**，否则任何先来的人都会拿到管理员。

内置页面（挂在 `AUTH_API_PREFIX` 下，默认根路径）：

| 路径 | 用途 |
| --- | --- |
| `/login` | 登录页（邮箱验证码 / Passkey） |
| `/account` | 账号中心：已绑定的第三方身份、OTP、Passkey 凭据 |
| `/admin/providers` | 第三方登录方式管理，仅管理员 |

## 当包引用

```go
import (
    "github.com/iautre/auth/pkg/authctx"
    "github.com/iautre/auth/pkg/authhttp"
    "github.com/iautre/gowk"
)

r := gowk.New()

module := authhttp.Setup(r, authhttp.SetupOptions{
    APIPrefix: "/auth",   // 业务 API 前缀，空表示根路径
    OAuth:     true,      // 挂 OAuth2/OIDC 协议端点（固定根路径）
    Federated: true,      // 挂第三方 OIDC 登录（固定根路径 /federated/...）
    MCPPath:   "/mcp",    // 挂 MCP 端点，空表示关闭
    Pages:     true,      // 挂内置登录页与账号中心
})

// 宿主自己的业务路由复用 Auth 的中间件
r.GET("/api/orders", module.CheckLogin, module.UserAuth, func(c *gin.Context) {
    user := authctx.ContextUser(c) // Id / Nickname / Group
    c.JSON(200, gin.H{"owner": user.Nickname, "admin": user.IsAdmin()})
})

gowk.RunHTTP(r)
```

`Module` 提供三个中间件：`CheckLogin` 只验 token 并把登录 ID 写进上下文，不查库；`UserAuth` 在其上按 ID 查出用户对象（`authctx.ContextUser` 才能取到值）；`CheckAdmin` 要求管理员组。

三个容易踩的点：

1. **迁移只会在 `gowk.Run` / `RunHTTP` / `RunGRPC` 里执行。** 自己 `r.Run()` 启动的话表永远不会建，接口会一路报错。
2. **协议端点固定在根路径**，不跟 `APIPrefix` 走。`/oauth2/*`、`/.well-known/*`、`/oidc/*`、`/federated/*` 都是约定俗成的路径，挪到前缀下面会让 issuer 和 discovery 语义变乱。
3. **`BASE_URL` 必须和客户端配置的 Issuer 完全一致**（含协议、端口，不带尾斜杠），否则 ID Token 的 `iss` 校验必然失败。

接入完成后，客户端侧可以用 `pkg/oidcclient` 省掉协议细节：

```go
client, _ := oidcclient.New(ctx, oidcclient.Config{
    Issuer: "https://auth.example.com", ClientID: "console",
    ClientSecret: "...", RedirectURL: "https://console.example.com/auth/callback",
})
authURL, verifier := client.AuthCodeURL(state, oidcclient.AuthURLOptions{})
// 回调里：
token, _ := client.Exchange(ctx, code, verifier)
info, _ := client.UserInfo(ctx, token.AccessToken)
```

## 端点

业务 API（挂在 `APIPrefix` 下）：

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/verification/send` | 发送邮箱验证码 |
| POST | `/login/code` | 邮箱验证码登录，账号不存在时按 `AUTH_AUTO_REGISTER` 决定是否建号 |
| POST | `/register/code` | 邮箱验证码注册（注册即登录） |
| POST | `/login` | 手机号或邮箱 + TOTP 动态口令登录（与 `/login/code` 并行；需先在账号里绑过 TOTP） |
| POST | `/logout` | 退出并清会话 |
| GET | `/user/info` | 当前用户信息 |
| PUT | `/user/profile` | 修改昵称等资料 |
| GET/DELETE | `/identities[/:provider]` | 已绑定的第三方身份，可解绑 |
| GET/POST/PATCH/DELETE | `/passkey/*` | Passkey 注册、登录、凭据管理 |
| GET/POST/DELETE | `/otp/*` | TOTP 凭据管理 |
| GET/POST/PUT/DELETE | `/admin/identity-providers[/:id]` | 第三方登录方式管理（管理员） |
| POST | `/mqtt/auth` | EMQX 认证回调 |

OAuth2 / OIDC：

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/.well-known/openid-configuration` | discovery |
| GET | `/.well-known/oauth-protected-resource[/mcp]` | RFC 9728 保护资源元数据 |
| GET | `/oidc/jwks` | 签名公钥 |
| GET | `/oidc/userinfo` | 用户信息（需 Bearer） |
| GET | `/oauth2/authorize` | 授权端点；未同意过的客户端先渲染确认页 |
| POST | `/oauth2/authorize` | 确认页提交（允许 / 拒绝） |
| POST | `/oauth2/token` | 授权码、刷新、client_credentials |
| POST | `/oauth2/register` | RFC 7591 动态客户端注册 |
| POST | `/oauth2/revoke` | RFC 7009 撤销 |
| POST | `/oauth2/introspect` | RFC 7662 内省 |
| GET | `/oauth2/end_session` | OIDC 登出 |
| POST/GET/PUT | `/oauth2/clients[/:id]` | 客户端管理，管理员用平台登录态鉴权 |
| DELETE | `/oauth2/clients/:id/disable` | 停用客户端 |
| POST | `/oauth2/clients/:id/regenerate-secret` | 重签 secret |

联邦登录：`GET /federated/providers`（登录页渲染按钮用）、`GET /federated/:provider/login`、`GET /federated/:provider/callback`。回调地址要提前在对方平台上登记。

## 环境变量

| 变量 | 必需性 | 说明 |
| --- | --- | --- |
| `DATABASE_DSN` | 必需 | PostgreSQL 连接串 |
| `BASE_URL` | 必需 | 对外访问地址，OIDC issuer 基准 |
| `AUTH_ENCRYPTION_KEY` | 生产必需 | 32 字节（base64 或 hex），加密第三方 provider 的 secret。`BASE_URL` 是 http 时可不配，会降级明文存储并告警 |
| `HTTP_SERVER_ADDR` | 可选 | 默认 `:8087` |
| `AUTH_API_PREFIX` | 可选 | 业务 API 前缀，默认根路径 |
| `AUTH_AUTO_REGISTER` | 可选 | 默认 `true`：验证码登录时账号不存在自动建号 |
| `AUTH_FEDERATED_ENABLED` | 可选 | 默认 `true`，关闭后不挂 `/federated/*` |
| `AUTH_SMTP_ADDR` | 发验证码必需 | `host:port`。465 端口走隐式 TLS，其余端口走 STARTTLS |
| `AUTH_SMTP_USERNAME` / `AUTH_SMTP_PASSWORD` / `AUTH_SMTP_FROM` | 同上 | SMTP 凭据与发件人 |
| `PASSKEY_RP_ID` | 用 Passkey 必需 | 域名，不带协议和端口 |
| `PASSKEY_ORIGINS` | 用 Passkey 必需 | 允许的源，逗号分隔 |
| `PASSKEY_RP_DISPLAY_NAME` | 可选 | 认证器里显示的名字 |
| `OTP_ISSUER` | 可选 | TOTP 显示的发证方 |
| `REDIS_ADDR` | 可选 | `OAUTH2_TOKEN_CACHE=redis` 时必需 |
| `OAUTH2_TOKEN_CACHE` | 可选 | 设为 `redis` 启用 token 只读缓存；配了但连不上会直接启动失败，不静默退化 |
| `EMQX_AUTH_KEY` / `EMQX_DEVICE_CREDENTIALS` | 仅 MQTT | EMQX 回调签名密钥、常驻设备静态凭据（`clientid:secret`，逗号分隔） |
| `DEPLOY_HOST` | 仅 `make deploy` | `user@host` |

## 接入第三方 MCP 客户端

MCP 客户端是用户机器上的独立进程，没有浏览器 cookie，也不知道授权服务器在哪，所以整条链靠一次 401 自举：

1. 客户端直接请求 `/mcp`，被拒。401 的 `WWW-Authenticate` 里带 `resource_metadata` 地址，指向 `/.well-known/oauth-protected-resource/mcp`。
2. 读元数据拿到授权服务器地址，再读 `/.well-known/openid-configuration`，发现 `registration_endpoint` 后自行注册（`POST /oauth2/register`），拿到 `client_id`——动态注册只接受 public client，不下发 secret，安全性由 PKCE 提供。
3. 拉起浏览器走授权码 + PKCE S256，换到 token 后每次请求带 `Authorization: Bearer ...`。

`/mcp` 上的工具目前只有三个：`auth_oidc_discovery`、`auth_oidc_jwks`、`auth_user_info`。都是只读的，前两个本来就是公开信息。

**已知限制**：token 端点没有 CORS，所以只支持原生客户端（Claude Desktop、Cursor、mcp-inspector 这类）。跑在浏览器里的 MCP 客户端连不通。RFC 8707 的 `resource` 参数会接受但不做 audience 绑定。

## 安全须知

- **动态注册是开放的**，任何人都能注册一个 public client。但这不等于能拿到你的身份——第一次授权会弹确认页，写明是哪个客户端在申请访问；允许后按 client 记 30 天 cookie，之后同一客户端不再打扰，拒绝则带 `access_denied` 回跳。
- **第三方 provider 的 secret 加密存库**（AES-256-GCM，`enc:v1:` 前缀）。没配 `AUTH_ENCRYPTION_KEY` 而 `BASE_URL` 不是 http 时进程拒绝启动，避免生产环境静默存明文。
- **动态注册的 `redirect_uri`** 只允许 https，或回环地址上的 http（原生客户端端口随机，所以不限端口），禁止 fragment 和 userinfo。
- **`/mcp` 的鉴权顺序**是先 OAuth2 access token、再回落浏览器会话。`client_credentials` 签出的 token（`user_id=0`）会被直接拒——MCP 授权必须落到具体用户。
