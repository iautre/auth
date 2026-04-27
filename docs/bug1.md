# Auth 项目代码检查报告（bug1）

本报告汇总对 `github.com/iautre/auth` 的一次系统性代码审查发现的 bug 与可优化点。审查范围：`cmd/`、`internal/`、`pkg/`、`weapp/`、`sql/`、`Dockerfile`、`Makefile`。

---

## 一、严重 Bug（影响正确性 / 安全）

### B1. OAuth2 `authorization_code` 授权流缺少 `redirect_uri` 二次校验

- 位置：`internal/service/service.go` → `handleAuthorizationCodeGrant` / `ValidateAuthorizationCode`（约 200-227、324-338 行）。
- 现状：`token` 端换码时只校验 `client_id` 与 code 的匹配，未校验请求里的 `redirect_uri` 与颁发 code 时记录的 `redirect_uri` 是否一致。
- 影响：违反 [RFC 6749 §4.1.3](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3)，在 redirect_uri 注册策略不严格时可能被跨 URI 利用（code 截获攻击）。
- 修复方向：`ValidateAuthorizationCode` 增加 `redirectURI` 参数，与 `authCode.RedirectUri.String` 严格比对；`auth_oauth2_authorization_code` 保留颁发时的 redirect_uri（已有字段，直接用）。

### B2. `authorization_code` / `refresh_token` 未校验 `client_secret`（confidential client 安全漏洞）

- 位置：`internal/service/service.go`
  - `handleAuthorizationCodeGrant`（约 325-338 行）：只调用 `ensureClientEnabled`。
  - `handleRefreshTokenGrant`（约 341-358 行）：同上。
- 对比：`handleClientCredentialsGrant`（约 373-429 行）里会比对 `client.Secret`。
- 影响：对 "confidential client"，持有 code 或 refresh_token 者可在不知 client_secret 情况下换取 token。
- 修复方向：统一加入 `client_secret` 校验（或按 `token_endpoint_auth_method` 区分 public/confidential client）。

### B3. PKCE 声明支持但完全未实现

- 位置：
  - `pkg/dto/dto.go`（第 66-76 行）`OAuth2TokenRequest.CodeVerifier` 有 `min=43,max=128` 校验。
  - `pkg/proto/auth.proto`（第 26-35 行）、`pkg/client/client.go`、`pkg/client/mount.go`、`internal/handler/handler.go`（第 286-297 行）都透传 `code_verifier`。
  - 但 `internal/service/service.go` 整个链路完全未使用该字段。
- 数据库：`auth_oauth2_authorization_code` 没有 `code_challenge` / `code_challenge_method` 字段。
- 影响：看起来"已支持 PKCE"，实际对任何 `code_verifier` 一概放行，严重的安全误导。
- 修复方向：新增字段 `code_challenge`、`code_challenge_method`（S256/plain）；`/oauth2/auth` 接收并落库；`/oauth2/token` 使用 `CodeVerifier` 反推并比对；必要时强制 public client 使用 PKCE。

### B4. `refresh_token` 轮换缺失 / 刷新时堆积无用 refresh_token 行

- 位置：`internal/service/service.go`
  - `handleRefreshTokenGrant`（约 341-358 行）与 `RefreshToken`（约 446-469 行）。
  - `generateAndStoreTokens`（约 230-285 行）每次都会同时新建 access_token 和 refresh_token 行。
- 现状：handler 刷新时拿到 `(accessToken, _, err)` —— 新生成的 refresh_token 被丢弃，response 回填 `req.RefreshToken`；新 refresh_token 行在 DB 中成为"孤儿"。
- 影响：
  1. 数据库 `auth_oauth2_refresh_token` 表体积膨胀；
  2. 原 refresh_token 到期后客户端必须重新登录，没有续期语义。
- 修复方向：
  - 要么刷新时仅生成 access_token（拆分 `generateAndStoreTokens`）；
  - 要么实现 refresh_token 轮换：生成新 refresh、吊销旧 refresh、返回新 refresh 给客户端（推荐）。

### B5. `OIDCUserInfo.email_verified` / `phone_number_verified` 硬编码为 true

- 位置：`internal/service/service.go` 第 541-557 行。
- 现状：
  ```go
  EmailVerified: true, // TODO: Implement email verification
  PhoneVerified: true, // TODO: Implement phone verification
  ```
- 影响：依赖 OIDC `email_verified` 做业务决策的 RP 会信任未验证的信息。
- 修复方向：至少改为 `user.IsVerified.Bool`（字段已存在），或按 email/phone 分别存储验证状态。

### B6. `UpdateOAuth2Client` 的 `enabled` 字段会被 Go 零值"隐性覆盖"

- 位置：
  - `pkg/dto/dto.go`（第 126-136 行）`OAuth2ClientUpdateParams.Enabled bool`。
  - `internal/service/service.go` `UpdateOAuth2Client`（约 817-853 行）。
  - `sql/queries/oauth2.sql` 注释明确要求"enabled 必须显式传入"。
- 现状：SQL 里 `enabled = $8::boolean` 无条件覆盖；Go `bool` 没有"未传"区分，只要调用方没传 `enabled`，就会将其置为 `false`，导致 client **被意外禁用**。
- 修复方向：
  - 改用 `*bool`，nil 表示"保持不变"；
  - 或在 SQL 里加 "nil/占位值不覆盖" 语义（例如用 `COALESCE` + 外部 flag）。

### B7. gRPC `Login`/`CheckToken` 的 `Device` 字段永远为空

- 位置：`internal/handler/handler.go`
  - 第 452-488 行 `GrpcHandler.Login`：构造 `nativeToken` 时未填 `Device`。
  - 第 405-430 行 `GrpcHandler.CheckToken`：原样返回 `t.Device`。
  - proto `LoginRequest` 也没有 device 字段。
- 影响：调用方依赖 `device` 做多端登录/设备识别时永远拿不到有效值，误以为接口有问题。
- 修复方向：proto 增加 `device` / `user_agent`；存 token 时写入；或直接去掉该字段。

### B8. `BasicAuthMiddleware` 对"无 Basic 凭据"的请求直接放行

- 位置：`internal/handler/handler.go`
  - 第 54-62 行 `BasicAuthMiddleware`。
  - 第 71-104 行 `validateBasicAuth`。
- 现状：`validateBasicAuth` 在 `ctx.GetString(gowk.ContextBasicAuthKey) == ""` 时直接 `return nil`，于是外层 `BasicAuthMiddleware` 会调用 `ctx.Next()`，相当于无凭据也放行。
- 路由：`internal/route/router.go` 第 35 行：

  ```35:35:/Users/autre/app/coding/auth/internal/route/router.go
  	ro.GET("/oauth2/auth", gowk.CheckLogin, u.BasicAuthMiddleware, o.OAuth2Auth)
  ```

  虽然前面有 `gowk.CheckLogin`，但逻辑上该中间件本身是"脆"的，容易被后来的调用者误用到不带 CheckLogin 的路由里。
- 修复方向：空凭据应当 `requireBasicAuth` 返回 401。并且要保证 `_basicAuthValidator` 已注册（auth 服务未调用 `SetBasicAuthValidator`）。

### B9. `OIDCDiscovery.response_types_supported` 与实际实现不一致

- 位置：`internal/service/service.go` 第 534 行：
  ```go
  ResponseTypesSupported: []string{"code", "id_token", "token id_token"},
  ```
- 对比：`pkg/dto/dto.go` 第 58 行的 `OAuth2AuthRequest.ResponseType` `binding:"oneof=code"` —— 只允许 `code`。
- 影响：依赖发现文档的 OIDC 客户端会尝试 `id_token` / `token id_token`，得到 400。
- 修复方向：要么实现 implicit / hybrid flow，要么在 Discovery 里只声明 `code`。

### B10. `Dockerfile` Go 版本与 `go.mod` 不一致

- 位置：
  - `Dockerfile` 第 1 行：`FROM golang:1.25.5-alpine3.22`。
  - `go.mod` 第 3 行：`go 1.26.1`。
- 影响：镜像构建时 `go build` 会报错 "go.mod requires go >= 1.26.1"。
- 修复方向：升级基础镜像到 `golang:1.26-alpine` 等版本，或降低 `go.mod` 声明的 Go 版本。

---

## 二、中等问题（质量 / 健壮性）

### M1. `weapp` 包存在多处错误，且包含空凭据，不应发布

- 位置：`weapp/weapp.go`。
- 问题：
  - 第 28-29 行 `appId` / `secret` 均为空常量；
  - 第 61-63 / 82-84 行 `if token.Errcode != 0 { return nil, err }`：此时 `err` 是上一次 `json.Unmarshal` 成功后的 nil，等于把错误**吞掉**返回 `(nil, nil)`；上层 `GetAccessToken` 会 `token = t` → `token.ExpiresTime` 空指针；
  - `GetUnlimitedQRCode` 实际请求的仍是 `cgi-bin/token`，命名与行为不符，疑似复制粘贴遗留；
  - 使用 `ioutil.ReadAll`（Go 1.16+ 已废弃），应改 `io.ReadAll`；
  - `GetAccessToken()` 无并发保护，多 goroutine 会并发调用微信接口并相互覆盖 `token` 全局变量；
  - 响应 body 未 `defer res.Body.Close()`。
- 修复方向：要么删掉整个包；要么重写 + 补配置。

### M2. `OIDCService` 被频繁以零值实例化，RSA 私钥缓存失效

- 位置：`internal/handler/handler.go` 多处：
  - 第 43 行 `var oidcService service.OIDCService` → `GenerateIDToken`；
  - `service.OAuth2Service.buildTokenResponse` 第 299 行同样 `var oidcService OIDCService`。
- 现状：`OIDCService` 通过 `sync.RWMutex` 缓存 `privateKey/kid`，但每次都是**新零值实例**，缓存形同虚设，每次签 JWT 都会多一次 DB 查询。
- 修复方向：做成进程级单例（`var defaultOIDCService = &OIDCService{}`）或在 handler 初始化时保存 `*OIDCService` 供所有路径复用。

### M3. `OIDCService.GetJwks` 使用 `context.Background()`

- 位置：`internal/service/service.go` 第 722-742 行。
- 影响：与请求链路脱钩，无超时、不可追踪。
- 修复方向：签名改为 `GetJwks(ctx context.Context)`，handler 传入 `ctx.Request.Context()`。

### M4. `UpdateLoginInfo` / `DeleteOAuth2AuthorizationCode` 错误被静默

- 位置：
  - `internal/service/service.go` 第 78-83 行：登录后更新登录信息失败仅注释"continue without updating"，没日志。
  - 第 219-224 行：授权码删除失败同样仅注释，若删除失败会导致 code 一码多用（安全敏感）。
- 修复方向：改为 `slog.WarnContext(ctx, ..., "err", err)`；授权码删除最好放到事务里，与"发放 token"保持同生同死。

### M5. `ExchangeToken` 三个分支错误类型不统一

- 位置：`internal/service/service.go`
  - `handleClientCredentialsGrant` 混用 `fmt.Errorf` 和 `gowk.NewError`（第 380、387、392、417 行）。
  - `handleAuthorizationCodeGrant` / `handleRefreshTokenGrant` 主要用 `gowk.NewError`。
- 影响：`gowk.Response` 对 `*ErrorCode` 有特殊处理（`errors.As`），`fmt.Errorf` 会走普通 error 分支，code 丢失。
- 修复方向：统一返回 `*gowk.ErrorCode`。

### M6. `BaseService.getQueries` 与构造函数里的 `queries` 字段并存且混用

- 位置：`internal/service/service.go`
  - `OAuth2Service` / `OAuth2ClientService` 构造函数里 `queries: db2.New(gowk.DB(ctx))`。
  - 但方法内仍大量调用 `o.getQueries(ctx)` 或直接 `db2.New(gowk.DB(ctx))`。
- 影响：两份 `*Queries` 语义、生命周期不一致，维护混乱。
- 修复方向：要么一律使用 `getQueries(ctx)`（轻量工厂），要么都使用缓存的 `queries`，二选一。

### M7. gin.Context 被当作 context.Context 直接传给 DB / Redis

- 位置：`internal/handler/handler.go` 几乎所有 handler；`internal/service/service.go` 在接收 `*gin.Context` 后直接传给 `pgx` / `redis`。
- 现状：`gin.Context` 的 `Done()/Deadline()/Err()` 并非来自请求；要拿到真正的请求 ctx 应使用 `ctx.Request.Context()`。
- 影响：下游的 ctx cancel、超时无法生效；日志/trace 也可能拿错 ctx。
- 修复方向：service 层统一接受 `context.Context`；handler 层调用时传 `ctx.Request.Context()`。

### M8. `OAuth2ClientResponse.Secret` 在 list 接口也会返回

- 位置：
  - `pkg/dto/dto.go` 第 88-114 行 `BuildOAuth2ClientResponse` 始终带 `Secret`。
  - `internal/handler/handler.go` `ListOAuth2Clients`（第 587-596 行）直接返回。
- 影响：list 接口会把所有 client 的 secret 广播给调用者。
- 修复方向：list 接口隐藏 secret；只在 Create / RegenerateSecret 接口一次性返回。

### M9. `supportsGrantType` 每次解析 JSON

- 位置：`internal/service/service.go` 第 432-444 行。
- 修复方向：client 的 `grant_types` 读多写少，可缓存解析结果；或改为数据库 JSONB / 单独表。

### M10. `isValidPhone` 正则每次都动态编译

- 位置：`internal/service/service.go` 第 745-748 行 `regexp.MatchString(...)`。
- 修复方向：`var phoneRe = regexp.MustCompile(...)` 提前编译，避免热路径重复开销。

### M11. `GetByAccount` 注释与实现不一致

- 位置：`internal/service/service.go` 第 88-97 行。
- 现状：注释宣称支持 phone or email，代码只做 phone。
- 修复方向：统一注释，或补齐 email 分支（同时完善 `GetByEmail`）。

### M12. `SSOService` 整体是占位实现

- 位置：`internal/service/service.go` 第 488-502 行 + `internal/handler/handler.go` `SSOLogin` 第 133-150 行。
- 现状：永远返回 `ErrSSONotImplemented`，handler 返回 501。
- 修复方向：若近期不做，建议从路由中摘除 `/sso/login`，避免对外暴露；或直接实现。

### M13. `auth_test.go` 是无效测试

- 位置：项目根目录 `auth_test.go`。
- 现状：`var oc service.OAuth2ClientService` 零值调 `CreateOAuth2Client`，内部 `s.queries` 为 nil 会 panic；而且用 `t.Error(err)` 把 nil 当错误输出。
- 修复方向：删除或改为真实集成测试（带 DB fixture）。

### M14. `weapp_test.go` 会真实访问微信 API

- 位置：`weapp/weapp_test.go`。
- 现状：没有 mock，CI 依赖外网；appId/secret 为空，微信会返回 40013，但测试仅 `t.Log`，不会失败。
- 修复方向：删除或用 `httptest` mock。

### M15. `client.MountRemote` 的 `/oauth2/token` 自行定义参数结构体

- 位置：`pkg/client/mount.go` 第 36-60 行。
- 现状：与 `dto.OAuth2TokenRequest` 大量重复，且没有 binding 校验。
- 修复方向：直接复用 `dto.OAuth2TokenRequest`。

### M16. remote 模式下，有两套"登录中间件"

- 位置：
  - `pkg/client/mount.go` 第 97-113 行 `remoteCheckLogin`。
  - `pkg/embed/embed.go` 第 207-223 行 `remoteLoginMW`。
- 现状：两个函数几乎一模一样，但错误提示文案、token 来源略有差别；`/user/info` 挂载在 `MountRemote` 内部自用那一套，其他路由走 `embed.Middlewares.Login`，行为不一致。
- 修复方向：抽一份共用实现。

### M17. `redisTokenPrefix` 在 auth 与 gowk 两处分别硬编码

- 位置：
  - `internal/handler/handler.go` 第 401 行。
  - `gowk/token.go` 第 181 行。
- 影响：两边要手工同步；gowk 一旦改前缀，auth 就失效。
- 修复方向：gowk 暴露 public 常量，auth 直接引用。

### M18. gRPC `LoginRequest` 与 native token 之间缺设备/端侧字段

- 位置：`pkg/proto/auth.proto` 第 99-109 行。
- 现状：只有 `account/code`，既不支持登录后写 device，也无法区分多端登录。
- 修复方向：proto 增加 `device/user_agent/ip` 字段；token 里对应存储。

### M19. `SSO` 路由暴露、`weapp` 打包进镜像

- 位置：`internal/route/router.go` 第 29 行 / `weapp/*`。
- 影响：未实现但路由可见、未用但二进制带入。
- 修复方向：未实现的功能暂不注册路由 + 默认不编译 `weapp`（或删）。

### M20. `pkg/constant/constant.go` 常量部分未被使用

- 位置：
  - `DISABLE` / `ENABLE`（第 25-28 行）未被任何代码引用。
  - `ErrAuthRequired` 等错误常量字符串也没有通过 `constant` 包使用，handler 和 middleware 里各自写字面量。
- 修复方向：删除未用常量，或统一替换字面量。

### M21. `Makefile` 明文写入 `DATABASE_DSN`

- 位置：`Makefile` 第 113 行。
- 影响：密码随命令行进入 `ps aux` 和 shell 历史；部署审计不友好。
- 修复方向：改为 `--env-file /etc/auth.env` 或 docker secret。

### M22. `Dockerfile` 使用 `scratch + UPX`

- 位置：`Dockerfile`。
- 影响：UPX 会破坏 Go 二进制元数据（pprof/symtab 等），运行时解压增加启动时间与内存；scratch 镜像无 shell、无 CA 证书，HTTPS 访问外部服务会出错。
- 修复方向：改 `distroless/static:nonroot` 或 `alpine`，去掉 UPX 或慎用。

### M23. `cmd/server.go` 健康检查 `/grpc-status` 硬编码端口

- 位置：`cmd/server.go` 第 63-68 行 `"port": "50051"`。
- 影响：实际 gRPC 端口可能不是 50051，输出误导。
- 修复方向：读 `*grpcPort` 变量返回。

### M24. `OIDCIDToken` payload 未带 phone，但 struct 定义了 `Phone`

- 位置：
  - `pkg/dto/dto.go` 第 200-210 行定义 `OIDCIDToken.Phone`。
  - `internal/service/service.go` 第 589-598 行 payload 构造没放 `phone`。
- 修复方向：明确要么删掉字段，要么在 payload 里按 scope 输出。

### M25. `client.base64Decode` 兼容 URL 与标准 base64，但过度宽松

- 位置：`pkg/client/client.go` 第 399-412 行。
- 现状：先替换 `-/_` 到 `+/`，再用 `base64.StdEncoding` 解；与 `rfc 7519` 的 `base64.RawURLEncoding` 相比偏"宽容"，容易掩盖格式错误。
- 修复方向：直接 `base64.RawURLEncoding.DecodeString`（必要时补齐 padding 后 `base64.URLEncoding`），并在错误时明确报出错 token。

---

## 三、小问题 / 风格

- `internal/handler/handler.go` 大量 `map[string]interface{}` 可用 `gin.H`。
- `dto.LoginRes` 定义但 `UserHandler.Login` 没用，返回的是 `jwtToken` 字符串，不对称。
- `Dockerfile`: `apk update && apk upgrade` 会增大镜像体积；`--no-cache add` 已经够用。
- `Dockerfile` 中 `as` 关键字建议用大写 `AS`（新版 BuildKit 会警告）。
- `cmd/server.go`: 用 `flag.Parse()` + 环境变量默认值，但 `gowk.SetHTTPServerAddr` 也读取了 env；有重复。
- `/oidc/userinfo` 同时支持 gRPC 与 HTTP，HTTP 与 `constant.StoreContextOAuth2Token` 写入的是 `user_id`，但 `OIDCUserInfo` handler 又从 `ctx.Get("user_id")` 取，字面量重复未使用常量（第 247 行）。
- `OIDCService.GenerateIDToken` 的 `json.Marshal` 错误被忽略 `headerJSON, _ := ...`；理论上 `map[string]interface{}` 序列化失败极少，但仍应返回 error。
- `OIDCService` 的 `time.Now().Unix()` 没有 `utc`；`iat/exp` 使用 Unix 秒数没问题，但可以加注释，避免后来者误用 `time.Now().UnixNano()`。
- `sql/schema.sql` 中 `auth_user.email` 没有唯一索引，但 `GetByEmail` 以 email 查；若要支持 email 登录需补唯一约束。
- `Makefile` 里的 `deploy` 通过 `docker save | ssh ... docker load` 传镜像，没有中间压缩（`gzip -1`）；大镜像会很慢。
- README.md 为空文件。

---

## 四、总结与修复范围建议

将问题分组，便于后续分批修复：

- **A 组（必须）**：B1 / B2 / B3 / B4 / B5 / B6 / B7 / B8 / B9 / B10 + M5。重点为安全与正确性。
- **B 组（推荐）**：A 组 + M1（weapp 重写或删除）+ M2（OIDCService 单例）+ M3/M4/M7（上下文与日志）+ M8（list 不返回 secret）+ M15/M16（remote 模式统一）+ M13/M14（无效测试）。
- **C 组（优化）**：B 组 + 其余 M* 与 "三、小问题" 全部。

### `weapp` 包去留建议

当前 `appId` / `secret` 都为空且代码含多处 bug，**短期不会被用到**。推荐直接删除整个 `weapp/` 目录；若将来要接入微信小程序登录，再单独规划：

1. 以 `appid + secret` 走环境变量配置；
2. token 加并发锁 / singleflight；
3. 增加响应体 `defer Close`、错误处理、超时 & 重试；
4. 写 mock 单测替代现在的外网调用测试。

---

生成时间：2026-04-24。
