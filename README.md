# 本地身份与访问控制服务

基于 FastAPI 的本地可运行身份与访问控制（IAM）引导工程。用进程内存储模拟身份源与
凭据，保证登录、会话续期与授权判定在并发、撤销和异常链路下给出一致且可解释的结论。

## 身份模型

- **User**：`user_id`、`username`、口令散列（盐化 SHA-256）、MFA 密钥、角色集合、
  `disabled` 标志、`token_version`（权限/状态版本号）。
- **Role**：名称 + 权限集合，权限形如 `document:read`；`*` 为通配（授予一切）。
  任何角色的权限集合变更都会递增全局 `policy_version`。
- **Resource**：`resource_id`、属主 `owner_id`、属性集合（如 `confidential`）。
- **Session**：长期会话，持有当前唯一有效的 `current_refresh_id`、签发时的
  `token_version` 快照、过期时间与撤销标志。

## 凭据与会话生命周期

凭据为 HMAC-SHA256 签名的 `base64url(payload).base64url(sig)` 结构。

- **登录** `POST /login`：校验口令 + TOTP 动态口令（30 秒步长，容忍 ±1 窗口），
  签发短期访问凭据（5 分钟）与长期会话的刷新凭据（7 天）。
  失败原因可区分：`user_not_found` / `bad_password` / `bad_mfa` / `account_disabled`。
- **续期** `POST /refresh`：**单次使用轮换**。旧 refresh token 的 jti 在 store 锁内
  原子作废并写入新 jti，因此并发续期最多一个成功。失败原因可区分：
  - `refresh_conflict`（HTTP 409）：上一次轮换后**宽限窗口内**（默认 2 秒）再次
    提交刚被消费的旧凭据——典型为两个请求几乎同时续期的撞车落败方，或在途重试。
    **可安全重试**：持赢家签出的新凭据重新续期即可，会话不受任何影响。
  - `session_reused`（HTTP 401）：宽限窗口**之外**重放已消费的凭据（或出现从未
    签发过的 jti）——按凭据复用这一**安全事件**处理：会话立即终止，之后这条会话
    不能再签出任何新凭据，绝不出现重放方与持方两个都还能用的会话。
  - 其余：`token_malformed` / `token_expired` / `session_not_found` /
    `session_revoked` / `account_disabled`。续期会刷新会话的权限快照。
- **登出** `POST /logout/{session_id}`：撤销会话，其访问凭据与刷新凭据立即失效。
- **禁用** `POST /admin/users/{user_id}/disable`：禁用账号、撤销其全部会话并递增
  `token_version`。
- **角色调整** `POST /admin/users/{user_id}/roles`：递增 `token_version`。
- **角色权限调整** `POST /admin/roles/{role_name}/permissions`：修改角色本身的
  权限集合，递增全局 `policy_version`。

**即时生效语义**：访问凭据内嵌签发时的 `token_version`（用户角色/状态版本）与
`policy_version`（角色权限集合版本）；授权时分别与用户当前版本、全局策略版本比对，
任一不一致即视为未认证。因此账号禁用、登出、用户角色调整、**角色权限集合调整**后，
未过期的旧访问凭据既不保留旧权限，也不会因策略更新静默获得新权限——必须重新
续期/登录。也就是说：收窄角色权限后旧凭据不能继续放行已移除的权限；放开角色权限后
旧凭据也不会凭空多出一项权限，得等续期拿到更新后的判定依据。

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

**幂等记账**：`POST /authorize` 接受可选的 `request_id`（幂等键）。调用方超时重发
或并发重复投递同一请求时，只要携带同一 `request_id` 与相同参数，拿到的就是首次
判定的结论，且账面上只记一次——不因重复投递多记，也不因去重少记（即使中途权限
已变更，同一请求的重试仍返回首次结论；新请求需用新的 `request_id` 才按最新状态
判定）。同一 `request_id` 换参数复用会被拒绝（HTTP 409）。不带 `request_id` 时
保持原有语义：每次调用独立判定、独立记账。

## 行为兼容说明

本轮新增对既有行为的影响范围：

- 续期失败细分：此前"旧 refresh token 再次提交"一律返回 `session_reused`；现在
  宽限窗口（默认 2 秒）内的重复提交返回 `refresh_conflict`（HTTP 409，可重试），
  窗口外的重放才返回 `session_reused` 并终止会话。调用方若原先只对 401 做重试，
  需把 409 也纳入可重试分支。
- 角色权限集合变更（新端点 `/admin/roles/{role_name}/permissions`）采用全局
  `policy_version` 保守失效：任何角色的权限变更都会使所有已签发访问凭据失效
  （包括未持有该角色的用户），续期即恢复。
- 登录、登出、禁用、越权判定、不带 `request_id` 的授权记账等其余行为不变。

## 本地验证

```bash
uv sync                  # 安装依赖
uv run pytest -q -s      # 运行测试（-s 查看关键输入与判定依据日志）
uv run uvicorn app.main:app --reload   # 启动服务
```

测试覆盖：并发续期（16 线程仅 1 个赢家，落败方为可重试的 `refresh_conflict`；
10 轮 × 8 线程连续轮换压测）、宽限窗口外重放判定为复用并终止会话、凭据重放、
登出/禁用/角色调整/角色权限集合调整的即时失效、提权不静默放行、越权访问、
并发判定与审计一致性、授权幂等（16 线程 × 10 轮重复投递只记一次账）、
HTTP 端到端链路。并发用例的日志（`pytest -s`）包含每轮的关键输入与判定依据。

演示数据：用户 `alice/alice-pw`（reader）、`bob/bob-pw`（editor），MFA 密钥分别为
`alice-mfa-secret` / `bob-mfa-secret`（用 `app.auth.totp_code` 生成动态口令）；
资源 `doc-public`、`doc-secret`（confidential）。
