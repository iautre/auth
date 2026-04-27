# Auth 项目代码检查报告（bug2）

本次独立审查针对 `github.com/iautre/auth` 仓库，按"严重 / 中等 / 轻微"分级给出问题清单。每条包含：问题、关键代码位置（带文件链接与行号）、影响、修复方向。

审查范围：`main.go`、`cmd/`、`internal/`、`pkg/`、`weapp/`、`sql/`、`Dockerfile`、`Makefile`、`go.mod`。

生成时间：2026-04-24。

---

## 一、严重（安全 / 正确性，必修）

### S1. `/oauth2/auth` 在 Basic Auth 通过时，`userID` 取到 0，授权码"无主"发放

- 位置：[internal/handler/handler.go](../internal/handler/handler.go) `OAuth2Handler.OAuth2Auth`（第 181-221 行）；[internal/route/router.go](../internal/route/router.go) 第 35 行；依赖 [../../gowk/token.go](../../gowk/token.go) `CheckLogin`（第 47-88 行）。
- 现状：
  - 路由链：`ro.GET("/oauth2/auth", gowk.CheckLogin, u.BasicAuthMiddleware, o.OAuth2Auth)`。
  - `gowk.CheckLogin` 在请求头为 `Authorization: Basic ...` 且 `_basicAuthValidator` 通过时，只会 `ctx.Set(ContextBasicAuthKey, decoded)` 并 `Next()`，**不会** 写入 `ContextLoginIdKey`。
  - `OAuth2Auth` 里 `userID := gowk.LoginId(ctx)` 拿到 0，却仍直接 `GenerateAuthorizationCode(..., userID, ...)` 落库并 302。
- 影响：走 Basic Auth 链路时，授权码 `user_id=0`；后续 `/oauth2/token` 换出的 access/refresh token、乃至 ID Token 的 `sub` 全部对应一个不存在的用户 0。这是直接可利用的身份混淆漏洞。
- 修复方向：
  1. `OAuth2Auth` 先判断 `userID <= 0`，返回 401 / 重定向到登录页；
  2. 或者 `BasicAuthMiddleware` 在成功时显式 `gowk.Login(ctx, user.ID)`（`validateBasicAuth` 里其实已经做了 `gowk.Login`，但这个 login 是在 Basic Auth 密码存在的分支里，而 `gowk.CheckLogin` 走 Basic 分支时并不会进入 `validateBasicAuth`，详见 S2）。

### S2. `BasicAuthMiddleware` 在无 Basic 凭据时"静默放行"

- 位置：[internal/handler/handler.go](../internal/handler/handler.go) `BasicAuthMiddleware`（第 54-62 行）、`validateBasicAuth`（第 71-104 行）。
- 现状：

```71:104:internal/handler/handler.go
func (u *UserHandler) validateBasicAuth(ctx *gin.Context) error {
	auth := ctx.GetString(gowk.ContextBasicAuthKey)
	if auth == "" {
		return nil
	}
	...
```

  - `validateBasicAuth` 在 `ContextBasicAuthKey` 为空时直接 `return nil`，上层 `BasicAuthMiddleware` 将 `err == nil` 理解为"通过"，`ctx.Next()`。
  - 配合 S1，`/oauth2/auth` 实际对"既没 Bearer 登录、也没有 Basic 凭据"的请求也无实质鉴权。
- 影响：中间件名为 Basic Auth 实际沦为占位；被复用到其他路由时会出现无鉴权直通。
- 修复方向：无凭据应直接走 `requireBasicAuth(ctx)` 返回 401；`BasicAuthMiddleware` 成功分支必须保证 `ContextLoginIdKey` 已写入。

### S3. OAuth2 token 端点未校验 `redirect_uri`

- 位置：[internal/service/service.go](../internal/service/service.go) `ValidateAuthorizationCode`（第 200-227 行）、`handleAuthorizationCodeGrant`（第 325-338 行）。
- 现状：换码时只比对 `authCode.ClientID == req.ClientID`，不校验 `req.RedirectURI` 与发码时记录的 `authCode.RedirectUri`。
- 影响：违反 [RFC 6749 §4.1.3](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3)。当 client 注册了多个 redirect_uri 时，攻击者截获的 code 可被换到另一个 redirect_uri，导致 code 被钓鱼站点重用。
- 修复方向：`ValidateAuthorizationCode` 增加 `redirectURI` 入参，严格比对 `authCode.RedirectUri.String == redirectURI`；`handleAuthorizationCodeGrant` 调用时传入 `req.RedirectURI`。

### S4. `authorization_code` / `refresh_token` grant 未校验 `client_secret`

- 位置：[internal/service/service.go](../internal/service/service.go) `handleAuthorizationCodeGrant`（第 325-338 行）、`handleRefreshTokenGrant`（第 341-358 行）、`ensureClientEnabled`（第 361-370 行）。
- 现状：两条链路只调 `ensureClientEnabled(ctx, clientID)`，仅查 `enabled` 字段；`req.ClientSecret` 完全被忽略。只有 `handleClientCredentialsGrant`（第 373-429 行）会比对 `client.Secret`。
- 影响：对 confidential client，只要拿到 `code` 或 `refresh_token` 就能换 token，`client_secret` 沦为摆设。
- 修复方向：
  - 基于 client 注册信息的 `token_endpoint_auth_method` 区分 confidential / public client；
  - confidential client 必须校验 `client_secret`；public client 配合 PKCE（见 S5）。

### S5. PKCE 声明支持但完全未实现

- 位置：
  - 参数定义：[pkg/dto/dto.go](../pkg/dto/dto.go) `OAuth2TokenRequest.CodeVerifier`（第 66-76 行）；
  - 透传：[pkg/proto/auth.proto](../pkg/proto/auth.proto)（第 26-35 行）、[pkg/client/client.go](../pkg/client/client.go) `OAuth2Token`（第 55-73 行）、[pkg/client/mount.go](../pkg/client/mount.go)（第 36-60 行）、[internal/handler/handler.go](../internal/handler/handler.go) `GrpcHandler.OAuth2Token`（第 286-297 行）；
  - Service：[internal/service/service.go](../internal/service/service.go) 从 `ExchangeToken` 到 `handleAuthorizationCodeGrant` 完整链路**未用** `CodeVerifier`；
  - DB：[sql/schema.sql](../sql/schema.sql) `auth_oauth2_authorization_code` 没有 `code_challenge` / `code_challenge_method` 列。
- 影响：`/oauth2/auth` 收不到 `code_challenge`，`/oauth2/token` 收到 `code_verifier` 也直接忽略。对外看起来"支持 PKCE"，实际对任何 `code_verifier` 一律放行——比不支持 PKCE 更危险，因为 SDK / RP 会误以为已有保护。
- 修复方向：
  - DB 增加 `code_challenge`、`code_challenge_method (S256|plain)` 列；
  - `OAuth2AuthRequest` 增加 `code_challenge` / `code_challenge_method`，`GenerateAuthorizationCode` 一并落库；
  - `ExchangeToken` 的 authorization_code 分支用 `CodeVerifier` 反推 `S256` 再与 DB 比对；
  - public client 强制要求 PKCE。

### S6. `UpdateOAuth2Client.Enabled` 会被 Go 零值"隐性覆盖"

- 位置：[pkg/dto/dto.go](../pkg/dto/dto.go) `OAuth2ClientUpdateParams`（第 126-136 行）、[internal/service/service.go](../internal/service/service.go) `UpdateOAuth2Client`（第 817-853 行）、[sql/queries/oauth2.sql](../sql/queries/oauth2.sql)（第 16-29 行）、[internal/db/oauth2.sql.go](../internal/db/oauth2.sql.go)（第 659-714 行）。
- 现状：
  - SQL：`enabled = $8::boolean, updated = NOW()`（无条件覆盖）；
  - Go DTO：`Enabled bool` 没有 `*bool`/sentinel，调用方只要不传 `enabled` 就是 `false`；
  - SQL 原始注释自己写着："enabled 必须显式传入"，但语言层无法保证这一点。
- 影响：调用方发一个只想改 `name` 的 PUT，就会把 client 意外禁用。
- 修复方向：
  - DTO 改 `Enabled *bool`，nil 表示"保持不变"；
  - 或 SQL 再加一层 sentinel（例如多传一个 `has_enabled` 标志），仅在标志为 true 时更新。

### S7. `OIDCDiscovery.response_types_supported` 与实际实现不一致

- 位置：[internal/service/service.go](../internal/service/service.go) `GetDiscoveryDocument`（第 512-538 行）；[pkg/dto/dto.go](../pkg/dto/dto.go) `OAuth2AuthRequest.ResponseType` `binding:"oneof=code"`（第 58 行）。
- 现状：Discovery 宣告 `response_types_supported = ["code", "id_token", "token id_token"]`，但 `/oauth2/auth` 只接受 `response_type=code`，其余直接被 `binding` 拒成 400。
- 影响：对接通用 OIDC client（读 Discovery 自动选 flow）的 RP 会尝试 implicit / hybrid，得到 400 Bad Request，误以为服务端 bug。
- 修复方向：只声明真实支持的；想要支持 implicit / hybrid 需补全 `/oauth2/auth` 的分支。

### S8. `OIDCUserInfo.email_verified` / `phone_number_verified` 硬编码为 `true`

- 位置：[internal/service/service.go](../internal/service/service.go) `OIDCService.GetUserInfo`（第 541-557 行）。
- 现状：

```548:556:internal/service/service.go
return &dto.OIDCUserInfo{
	...
	EmailVerified:     true, // TODO: Implement email verification
	...
	PhoneVerified:     true, // TODO: Implement phone verification
	...
}, nil
```
- 影响：RP 按照 OIDC 规范把 `email_verified=true` 作为"可信邮箱"判据做账号合并、找回密码；此处硬编码会把未验证用户误判为已验证。
- 修复方向：用 `user.IsVerified.Bool` 或新增分别存 email/phone 验证状态的列。

### S9. `handleRefreshTokenGrant` 每次刷新都写入一条"孤儿" refresh_token 行

- 位置：[internal/service/service.go](../internal/service/service.go) `handleRefreshTokenGrant`（第 341-358 行）、`generateAndStoreTokens`（第 230-285 行）、`RefreshToken`（第 446-469 行）。
- 现状：

```353:357:internal/service/service.go
accessToken, _, err := o.generateAndStoreTokens(ctx, token.ClientID, token.UserID, token.Scope)
if err != nil {
	return nil, err
}
return o.buildTokenResponse(ctx, accessToken, req.RefreshToken, token.Scope, false, 0, "", "")
```
  - `generateAndStoreTokens` 固定会同时 `CreateOAuth2Token` + `CreateOAuth2RefreshToken`，返回新 refresh 被丢弃；
  - 响应给客户端的仍是 `req.RefreshToken`，老 refresh 未吊销，新 refresh 行成了无人使用的垃圾数据。
- 影响：
  1. `auth_oauth2_refresh_token` 表膨胀；
  2. 没有 refresh_token 轮换，原 refresh 过期即被迫重新登录；
  3. 若未来启用 refresh 轮换（RFC 6749 §6），现存"孤儿"行会干扰判定。
- 修复方向：
  - 拆 `generateAndStoreTokens`，refresh 分支走"只新建 access token"的 helper；
  - 或实现标准 refresh rotation：生成新 refresh → 吊销旧 refresh → 返回新 refresh（推荐）。

### S10. `Dockerfile` 与 `go.mod` Go 版本不一致，镜像必定构建失败

- 位置：[Dockerfile](../Dockerfile) 第 1 行 `FROM golang:1.25.5-alpine3.22`；[go.mod](../go.mod) 第 3 行 `go 1.26.1`。
- 影响：`go build` 会直接报 `go.mod requires go >= 1.26.1`。CI / 线上构建全量失败。
- 修复方向：升级基础镜像到 `golang:1.26-alpine3.22` 或更高；或反过来把 `go.mod` 的 Go 声明降到 1.25。

### S11. gRPC `Login` / `CheckToken` 的 `device` 字段永远为空

- 位置：
  - [internal/handler/handler.go](../internal/handler/handler.go) `GrpcHandler.Login`（第 453-488 行）：构造 `nativeToken` 时未设 `Device`；
  - `GrpcHandler.CheckToken`（第 405-430 行）：原样透传 `t.Device`；
  - [pkg/proto/auth.proto](../pkg/proto/auth.proto) `LoginRequest`（第 99-102 行）没有 device 字段。
- 影响：调用方（如 console）想靠 `device` 做多端登录 / 会话列表时永远拿空，容易被误会为接口 bug。
- 修复方向：要么在 proto `LoginRequest` 加 `device / user_agent / ip`，落库到 `nativeToken.Device`；要么干脆从 proto 和 handler 中移除该字段，避免虚假声明。

---

## 二、中等（健壮性 / 可维护性 / 性能）

### M1. `OIDCService` 内存缓存被"零值实例化"反复绕过

- 位置：[internal/handler/handler.go](../internal/handler/handler.go) `UserHandler.Login`（第 44 行 `var oidcService service.OIDCService`）；[internal/service/service.go](../internal/service/service.go) `buildTokenResponse`（第 299 行 `var oidcService OIDCService`）、`OIDCService` 结构定义（第 505-510 行）。
- 现状：`OIDCService` 用 `sync.RWMutex` + `privateKey/kid/keyLoaded` 做进程级缓存，但每次调用都是新的零值实例，`keyLoaded == false`，于是每次签 JWT 都要走一次 `GetLatestOIDCJwk` 查 DB。
- 影响：高并发下对 `auth_oidc_jwk` 的 QPS 线性放大；缓存语义形同虚设。
- 修复方向：做进程级单例（`var defaultOIDCService = &OIDCService{}`）；或在 `NewOAuth2Handler` / `NewGrpcHandler` 里统一初始化并复用。

### M2. `OIDCService.GetJwks` 使用 `context.Background()`

- 位置：[internal/service/service.go](../internal/service/service.go) `GetJwks`（第 722-742 行）。
- 现状：直接 `db2.New(gowk.DB(context.Background()))`、`GetActiveOIDCJwks(context.Background())`。
- 影响：与请求链路脱钩，请求取消 / 超时无法传递；日志 / trace 拿不到 request id。
- 修复方向：签名改为 `GetJwks(ctx context.Context)`，handler 传 `ctx.Request.Context()`。

### M3. service 层静默吞错：`DeleteOAuth2AuthorizationCode` / `UpdateLoginInfo`

- 位置：
  - [internal/service/service.go](../internal/service/service.go) `ValidateAuthorizationCode`（第 219-224 行）：授权码删除失败仅注释 `// In production, you might want to handle this more carefully`；
  - `UserService.Login`（第 78-83 行）：登录后更新登录信息失败仅注释 `// Log error but don't fail login`。
- 影响：
  - 授权码删除失败 ⇒ 同一 code 可能被再次换 token（违反 RFC 6749 code 单次性），安全敏感；
  - 登录信息更新失败 ⇒ 无日志、无告警，线上只能靠对比 `last_login_at` 发现问题。
- 修复方向：
  - 至少加 `slog.WarnContext(ctx, ..., "err", err)`；
  - 授权码更推荐用事务把"校验 + 删除 + 发 token"打包，保证原子性。

### M4. `ExchangeToken` 三分支错误类型混用

- 位置：[internal/service/service.go](../internal/service/service.go)。
  - `handleClientCredentialsGrant`（第 373-429 行）混用 `fmt.Errorf` 与 `gowk.NewError`（如第 380、387、392、417 行）；
  - `handleAuthorizationCodeGrant` / `handleRefreshTokenGrant` 基本用 `gowk.NewError`。
- 影响：`gowk.Response` 通过 `errors.As(err, &ec)` 提取 `*ErrorCode`；`fmt.Errorf` 会落到兜底分支，丢失 code / 自定义状态。
- 修复方向：统一返回 `*gowk.ErrorCode`，或统一 `gowk.NewError`。

### M5. `BaseService.getQueries` 与 service 结构体的 `queries` 字段并存且混用

- 位置：[internal/service/service.go](../internal/service/service.go)
  - `BaseService.getQueries(ctx)`（第 34-36 行）；
  - `OAuth2Service.queries`（第 134-145 行）、`OAuth2ClientService.queries`（第 751-761 行）。
  - 同一方法里同时出现 `o.getQueries(ctx)` 和 `db2.New(gowk.DB(ctx))`（如 `generateAndStoreTokens` 第 232、405 行）。
- 影响：两份 `*Queries` 生命周期 / ctx 语义不一致，新人修改时容易踩坑。
- 修复方向：二选一并统一——推荐保留轻量工厂 `getQueries(ctx)`，删除结构体上的 `queries` 字段。

### M6. handler 把 `*gin.Context` 当 `context.Context` 传给 DB / Redis

- 位置：[internal/handler/handler.go](../internal/handler/handler.go) 几乎所有 handler 直接用 `ctx *gin.Context` 作为 `ctx.Request.Context()` 的替代；service 层同样。
- 影响：`gin.Context` 的 `Done()/Deadline()/Err()` 不反映请求生命周期，下游 pgx / redis 不会因为客户端断连提前释放。
- 修复方向：service 层签名统一收 `context.Context`；handler 调用传 `c.Request.Context()`。

### M7. `ListOAuth2Clients` 把所有 client 的 `secret` 一并返回

- 位置：[pkg/dto/dto.go](../pkg/dto/dto.go) `BuildOAuth2ClientResponse`（第 102-114 行）；[internal/handler/handler.go](../internal/handler/handler.go) `ListOAuth2Clients`（第 587-596 行）。
- 影响：列表接口会把所有 client 的 secret 广播给调用者。Admin 面板被 XSS / token 泄露后可直接取走全站 secret。
- 修复方向：
  - 拆两个响应 DTO：`OAuth2ClientListItem`（不含 secret）与 `OAuth2ClientResponse`（含 secret，仅 create / regenerate 用）；
  - `List` / `Get` 默认隐藏 secret。

### M8. `supportsGrantType` / `ValidateOAuth2AuthRequest` 每次请求解析 JSON 文本

- 位置：[internal/service/service.go](../internal/service/service.go) `supportsGrantType`（第 432-444 行）、`ValidateOAuth2AuthRequest`（第 173-198 行）。
- 现状：`redirect_uris` / `grant_types` / `scopes` 统一以 `text` 存 JSON；每次校验都 `json.Unmarshal`。
- 影响：热路径额外 allocation；schema 亦无法利用 PG 的 JSONB 索引。
- 修复方向：
  - DB schema 改 `jsonb`（或规范化为子表）；
  - Go 侧用 LRU 缓存解析结果。

### M9. `isValidPhone` 每次请求动态编译正则

- 位置：[internal/service/service.go](../internal/service/service.go) `isValidPhone`（第 745-748 行）。
- 现状：`regexp.MatchString(...)` 每次都重新编译。
- 修复方向：`var phoneRe = regexp.MustCompile(\`^1[3-9]\d{9}$\`)` 提前编译。

### M10. `pkg/client/mount.go` 的 `/oauth2/token` 自定义结构体，缺 binding 校验且与 DTO 重复

- 位置：[pkg/client/mount.go](../pkg/client/mount.go) 第 36-60 行。
- 现状：匿名 struct 除 `grant_type` 外其余字段均无 `binding`，与 `dto.OAuth2TokenRequest`（[pkg/dto/dto.go](../pkg/dto/dto.go) 第 66-76 行）大量重复。
- 影响：maintenance drift：后续修改只动一处就会行为分叉；参数合法性也依赖远端 gRPC 再报错。
- 修复方向：复用 `dto.OAuth2TokenRequest`；或把公共请求结构体下沉到一个 "public DTO" 包。

### M11. remote 模式下存在两份几乎一样的登录校验中间件

- 位置：
  - [pkg/client/mount.go](../pkg/client/mount.go) `remoteCheckLogin`（第 97-113 行）——挂载在 `MountRemote` 内部供 `/user/info` 使用；
  - [pkg/embed/embed.go](../pkg/embed/embed.go) `remoteLoginMW`（第 207-223 行）——供 `Middlewares.Login` 使用。
- 现状：两者都通过 `CheckToken` gRPC 校验 token，错误文案、写 key 名字略有差异。
- 影响：两条路径行为不完全一致；维护时必须同步改两处。
- 修复方向：抽到 `authclient` 包或 `embed` 里共用一份。

### M12. `redisTokenPrefix` 在 auth 与 gowk 两处硬编码

- 位置：
  - [internal/handler/handler.go](../internal/handler/handler.go) 第 401 行 `const redisTokenPrefix = "ATOKEN_TOKEN_"`；
  - gowk 内部 `token.go`（同名前缀）。
- 影响：任一方改前缀另一方立即失效；且无法 compile-time 约束。
- 修复方向：gowk 导出 public 常量（例如 `RedisTokenPrefix`），auth 直接引用。

### M13. `weapp` 包多处 bug，不可发布

- 位置：[weapp/weapp.go](../weapp/weapp.go)、[weapp/weapp_test.go](../weapp/weapp_test.go)。
- 问题汇总：
  1. `appId` / `secret` 为空常量（第 28-29 行），永远请求失败；
  2. `json.Unmarshal` 成功后又 `if token.Errcode != 0 { return nil, err }`（第 61-63、82-84 行），此时 `err` 已是 nil，**错误被彻底吞掉**，调用者拿到 `(nil, nil)`，外层 `token = t` 随后 `token.ExpiresTime` 空指针 / 字段缺失；
  3. `GetUnlimitedQRCode` 请求的仍是 `cgi-bin/token`（第 68-87 行），名不符实；
  4. 全局 `token *Token` 无并发保护，多 goroutine 并发调用会相互覆盖；
  5. `ioutil.ReadAll` 已废弃（Go 1.16+ 推荐 `io.ReadAll`）；
  6. `http.Get` 返回的 `res.Body` 没有 `defer res.Body.Close()`，连接复用受损；
  7. `weapp_test.go` 真实请求微信（无 mock），CI 强依赖外网。
- 修复方向：要么删掉整个 `weapp/` 目录（当前代码未被任何业务引用），要么重写 + 补配置 + 并发保护 + mock 测试。

### M14. `pkg/client/client.go.base64Decode` 与 JWT 规范偏差

- 位置：[pkg/client/client.go](../pkg/client/client.go) `base64Decode`（第 399-412 行）。
- 现状：先把 `-/_` 替换成 `+//`，再用 `base64.StdEncoding` 解；RFC 7519 JWT 使用 `base64.RawURLEncoding`。
- 影响：对非法 JWT 的宽容会掩盖真实格式错误；跨语言/跨实现比对难度增加。
- 修复方向：直接 `base64.RawURLEncoding.DecodeString(s)`；或 `base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))`。

### M15. `GenerateIDToken` payload 缺 `phone`，但 `OIDCIDToken` 结构体定义了 `Phone`

- 位置：[pkg/dto/dto.go](../pkg/dto/dto.go) `OIDCIDToken`（第 200-210 行，含 `Phone string`）；[internal/service/service.go](../internal/service/service.go) `GenerateIDToken`（第 589-598 行）只构造 `iss/sub/aud/exp/iat/nonce/name/email`，没有 `phone`。
- 影响：字段定义与真实 payload 不一致，新人按 struct 推断会误以为 phone 已签进 JWT。
- 修复方向：payload 按照规范或业务需要补充 `phone`；或反之删除 `OIDCIDToken.Phone`。

### M16. `cmd/server.go` `/grpc-status` 硬编码端口

- 位置：[cmd/server.go](../cmd/server.go) 第 63-68 行。
- 现状：无论 `*grpcPort` 实际是什么，响应里固定 `"port": "50051"`。
- 影响：运维读取此接口用于健康检查、日志排查时会被误导。
- 修复方向：闭包捕获 `*grpcPort` 变量再返回。

### M17. `SSOLogin` 路由永久 501，仍对外暴露

- 位置：[internal/route/router.go](../internal/route/router.go) 第 29 行 `ro.POST("/sso/login", u.SSOLogin)`；[internal/service/service.go](../internal/service/service.go) `SSOService.LoginWithProvider`（第 500-502 行）。
- 现状：实现永远 `return nil, ErrSSONotImplemented`，handler 返回 501。
- 影响：能被扫描到的"未完成功能"增加攻击面与支持成本；若后续有人新增逻辑容易被绕过鉴权直接生效。
- 修复方向：短期从路由中摘除，或实现后再放出。

### M18. `/oidc/userinfo` HTTP handler 使用字面量 `"user_id"`，未复用常量

- 位置：[internal/handler/handler.go](../internal/handler/handler.go) `OAuth2Handler.OIDCUserInfo`（第 245-257 行）；[pkg/constant/constant.go](../pkg/constant/constant.go) 已有 `ContextUserID = "user_id"`（第 5 行）。
- 影响：常量层没有约束力；未来改常量名会漏改这里。
- 修复方向：替换为 `constant.ContextUserID`。

### M19. `auth_test.go` 零值 service 会 panic，且 `t.Error(err)` 把 nil 当错误

- 位置：[auth_test.go](../auth_test.go)。
- 现状：`var oc service.OAuth2ClientService` 零值调 `CreateOAuth2Client`，其内部 `s.queries` 为 nil（实际代码走 `s.getQueries(ctx)`，但 `gowk.DB(ctx)` 在缺少初始化时同样会炸）；末尾 `t.Error(err)` 与 `t.Log(o)` 把 `err == nil` 情况也当错误记录。
- 影响：`go test ./...` 失败或产生虚假错误。
- 修复方向：删除或改写为带 DB fixture 的集成测试。

### M20. `weapp_test.go` 真实访问外网

- 位置：[weapp/weapp_test.go](../weapp/weapp_test.go)。
- 修复方向：改用 `httptest.NewServer` mock 微信域名，或直接删除。

---

## 三、轻微（风格 / 文档 / 一致性）

### L1. `dto.LoginRes` 定义但从未返回

- 位置：[pkg/dto/dto.go](../pkg/dto/dto.go) `LoginRes`（第 22-28 行）；[internal/handler/handler.go](../internal/handler/handler.go) `UserHandler.Login`（第 29-52 行）实际返回的是一段字符串 JWT。
- 建议：删除 `LoginRes`，或改造 `Login` 按 `LoginRes` 结构返回 `{token, userId, nickname, ...}`。

### L2. handler 里 `map[string]interface{}` 可用 `gin.H`

- 位置：[internal/handler/handler.go](../internal/handler/handler.go) `ResetOTPCode`（第 162-166 行）、`RegenerateClientSecret`（第 630-635 行）等。
- 建议：统一 `gin.H{...}`，短、无导入成本。

### L3. `constant` 包有未被引用的符号

- 位置：[pkg/constant/constant.go](../pkg/constant/constant.go)。
- 现状：`DISABLE` / `ENABLE`（第 25-28 行）、`ErrAuthRequired` / `ErrAdminRequired` 等错误文案常量（第 13-22 行）在仓库里没有被任何代码引用；handler 里都是硬编码字符串（如 `"Authentication required"`、`"Admin access required"`）。
- 建议：要么删除未用常量；要么把 handler / middleware 里的字面量替换为常量，保持一致性。

### L4. `GenerateIDToken` 丢弃 `json.Marshal` 错误

- 位置：[internal/service/service.go](../internal/service/service.go) 第 600-601 行。
- 现状：`headerJSON, _ := json.Marshal(header)`、`payloadJSON, _ := json.Marshal(payload)`。
- 建议：即便 `map[string]interface{}` 序列化失败概率极小，也应显式处理错误，至少 `slog.ErrorContext`。

### L5. `auth_user.email` 未建唯一索引

- 位置：[sql/schema.sql](../sql/schema.sql) 第 8-24、101-103 行。
- 现状：email 列只有普通索引 `idx_auth_user_email`，`GetByEmail` 以 email 作为主键查询，schema 允许重复邮箱。
- 建议：若打算支持 email 登录，需加 `UNIQUE (email) WHERE email IS NOT NULL`；同步 `GetByEmail` 查询逻辑与重复校验。

### L6. `Makefile deploy` 把数据库连接串明文放命令行

- 位置：[Makefile](../Makefile) 第 104-116 行。
- 现状：`-e DATABASE_DSN="postgres://postgres:...@postgres:5432/auth?..."` 直接作为 shell 参数注入。
- 影响：
  - 服务器上 `ps aux` 可见密码；
  - Git 仓库里明文存在生产密码。
- 建议：换成 `--env-file /etc/auth.env` 或 docker secret；Git 版本里去掉密码。

### L7. `Makefile deploy` 使用 `docker save | ssh docker load`，无压缩

- 位置：[Makefile](../Makefile) 第 96-101 行。
- 建议：大镜像传输慢，可中间插 `gzip -1`，如 `docker save ... | gzip -1 | ssh ... 'gunzip | docker load'`。

### L8. `Dockerfile` 用 `scratch + UPX`

- 位置：[Dockerfile](../Dockerfile)。
- 风险：
  - UPX 压缩会破坏 Go 二进制元数据（pprof、runtime symtab、GOTRACEBACK 信息），启动时需解压、占 RAM 更高；
  - `scratch` 没有 CA 证书，如有 HTTPS 外呼会报 `x509: certificate signed by unknown authority`。
  - `apk update && apk upgrade` 会拉动大量 apk 数据，镜像构建变慢。
- 建议：
  - 改 `gcr.io/distroless/static:nonroot` 或 `alpine:3.22`，保留基础 CA；
  - 去掉 UPX，或仅在极度追求镜像尺寸且接受启动延迟时使用；
  - 把 `apk update && apk upgrade` 精简为 `apk add --no-cache`。

### L9. `Dockerfile` `as` 建议大写 `AS`

- 位置：[Dockerfile](../Dockerfile) 第 1、26 行。
- 建议：新版 BuildKit 对小写 `as` 会发 warning，用大写 `AS`。

### L10. `cmd/server.go` 端口参数 env 与 gowk 内部 env 重复

- 位置：[cmd/server.go](../cmd/server.go) 第 28-34 行。
- 现状：`getEnvOrDefault("HTTP_SERVER_ADDR", ...)` + `flag.String` + `gowk.SetHTTPServerAddr(*httpPort)`；而 gowk 内部可能已有同名 env 解析。
- 建议：确定一处"权威"的端口解析；避免两层解析导致调试困难。

### L11. `auth_oauth2_authorization_code` 无复合索引 `(client_id, expires)`

- 位置：[sql/schema.sql](../sql/schema.sql) 第 104-110 行。
- 现状：只为 `client_id`、`expires` 建了独立普通索引。
- 建议：高频查询 `WHERE code = $1 AND expires > NOW()` 已命中 PK；`CleanupExpiredAuthorizationCodes` 按 `expires <= NOW()` 扫描，可考虑 partial index；不紧急。

### L12. `README.md` 为空

- 位置：[README.md](../README.md)。
- 建议：至少写明项目定位、启动方式、主要 env、`make help` 指引。

### L13. `pkg/util/otp.go` 在 `crypto/rand` 失败时 panic

- 位置：[pkg/util/otp.go](../pkg/util/otp.go) `GenerateOTPSecret`（第 64-77 行）。
- 现状：`panic("failed to read crypto/rand: ...")`。
- 说明：从技术上 `crypto/rand` 失败是致命，确实可以 panic；但业务接口里的单个请求触发 panic 会把整个 gin goroutine 中断，建议返回 error，由上层决定。
- 建议：改为返回 `(string, error)` 并在 `ResetOTPCode` 里返回 500；保留 panic 作为降级。

---

## 四、分组与修复优先级建议

- **A 组（必修 · 安全 / 正确性）**：S1–S11 全部 + M3（代码删除静默失败）。
- **B 组（建议 · 关键健壮性）**：A 组 + M1（OIDCService 单例）+ M2（GetJwks ctx）+ M4（统一错误类型）+ M6（context 传递）+ M7（list 隐藏 secret）+ M11/M12（remote 中间件 & Redis prefix 统一）+ M13/M19/M20（weapp / 无效测试）。
- **C 组（优化 · 性能 / 维护）**：B 组 + 其余 M* 条目。
- **D 组（风格 / 文档）**：L1–L13。

### 关于 `weapp` 包

当前 `appId/secret` 为空、代码多处 bug 且业务主链路未调用。建议直接删除整个 `weapp/` 目录，后续如需接入微信小程序再单独规划（环境变量配置、`singleflight` 防并发重复获取 access_token、`defer res.Body.Close()`、超时重试、mock 单测）。
