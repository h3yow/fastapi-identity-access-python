# 本地身份与访问控制服务

基于 FastAPI 的本地可运行身份与访问控制（IAM）引导工程。用进程内存储模拟身份源与
凭据，保证登录、会话续期与授权判定在并发、撤销和异常链路下给出一致且可解释的结论。

## 身份模型

- **User**：`user_id`、`username`、口令散列（盐化 SHA-256）、MFA 密钥、角色集合、
  `disabled` 标志、`token_version`（权限/状态版本号）。
- **Role**：名称 + 权限集合，权限形如 `document:read`；`*` 为通配（授予一切）。
- **Resource**：`resource_id`、属主 `owner_id`、属性集合（如 `confidential`）。
- **Session**：长期会话，持有当前唯一有效的 `current_refresh_id`、签发时的
  `token_version` 快照、过期时间与撤销标志。

## 凭据与会话生命周期

凭据为 HMAC-SHA256 签名的 `base64url(payload).base64url(sig)` 结构。

- **登录** `POST /login`：校验口令 + TOTP 动态口令（30 秒步长，容忍 ±1 窗口），
  签发短期访问凭据（5 分钟）与长期会话的刷新凭据（7 天）。
  失败原因可区分：`user_not_found` / `bad_password` / `bad_mfa` / `account_disabled`。
- **续期** `POST /refresh`：**单次使用轮换**。旧 refresh token 的 jti 在 store 锁内
  原子作废并写入新 jti，因此并发续期最多一个成功，重放得到 `session_reused`。
  其余失败原因：`token_malformed` / `token_expired` / `session_not_found` /
  `session_revoked` / `account_disabled`。续期会刷新会话的权限快照。
- **登出** `POST /logout/{session_id}`：撤销会话，其访问凭据与刷新凭据立即失效。
- **禁用** `POST /admin/users/{user_id}/disable`：禁用账号、撤销其全部会话并递增
  `token_version`。
- **角色调整** `POST /admin/users/{user_id}/roles`：递增 `token_version`。

**即时生效语义**：访问凭据内嵌签发时的 `token_version`；授权时与用户当前版本比对，
不一致即视为未认证。因此账号禁用、登出或角色调整后，未过期的旧访问凭据既不保留
旧权限，也不会因策略更新静默获得新权限——必须重新续期/登录。

## 授权规则

`POST /authorize` 返回四种语义明确的结果：

| 结果 | 含义 |
|---|---|
| `unauthenticated` | 未携带凭据、凭据无效/过期/版本过期、会话已撤销或账号已禁用 |
| `not_found` | 已认证，但目标资源不存在（不对未认证者泄露存在性） |
| `forbidden` | 已认证但权限不足，审计中记录缺失的具体权限 |
| `allowed` | 放行，审计中记录判定依据 |

判定规则：资源属主隐式拥有一切权限；角色含 `*` 通配放行；普通资源需要
`permission`，带属性 `attr` 的资源额外需要 `permission:attr`。

**并发一致性**：判定与审计写入在同一把 store 锁内完成，同一请求的判定结果与审计
记录一一对应，不会出现部分授权或重复记账。审计可通过 `GET /audit` 查看。

## 本地验证

```bash
uv sync                  # 安装依赖
uv run pytest -q -s      # 运行测试（-s 查看关键输入与判定依据日志）
uv run uvicorn app.main:app --reload   # 启动服务
```

测试覆盖：并发续期（16 线程仅 1 个赢家）、凭据重放、登出/禁用/角色调整的即时
失效、提权不静默放行、越权访问、并发判定与审计一致性、HTTP 端到端链路。

演示数据：用户 `alice/alice-pw`（reader）、`bob/bob-pw`（editor），MFA 密钥分别为
`alice-mfa-secret` / `bob-mfa-secret`（用 `app.auth.totp_code` 生成动态口令）；
资源 `doc-public`、`doc-secret`（confidential）。
