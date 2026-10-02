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
  原子作废并写入新 jti，因此并发续期最多一个成功。失败原因可区分：
  - `concurrent_conflict`（HTTP 409）：提交的 jti 在冲突窗口（默认 2 秒）内刚被
    另一个在途请求消费——两个请求撞车，属于**可重试的临时冲突**，会话不受影响；
  - `session_reused`（HTTP 401）：jti 早已被消费（超出冲突窗口）或来路不明——
    按**凭据复用**（安全事件）处理，一经判定该会话**立即永久作废**，之后不得再
    签出任何新凭据（含当前仍有效的 refresh token），其访问凭据也同步失效，
    绝不出现两个都还能用的会话；
  - 其余：`token_malformed` / `token_expired` / `session_not_found` /
    `session_revoked` / `account_disabled`。续期会刷新会话的权限快照。
- **登出** `POST /logout/{session_id}`：撤销会话，其访问凭据与刷新凭据立即失效。
- **禁用** `POST /admin/users/{user_id}/disable`：禁用账号、撤销其全部会话并递增
  `token_version`。
- **角色调整** `POST /admin/users/{user_id}/roles`：递增 `token_version`。
- **角色权限调整** `POST /admin/roles/{role_name}/permissions`：修改角色本身的
  权限集合（用户角色不变），持有该角色的所有用户 `token_version` 递增。

**即时生效语义**：访问凭据内嵌签发时的 `token_version`；授权时与用户当前版本比对，
不一致即视为未认证。因此账号禁用、登出、角色调整**或角色权限集合变更**后，未过期
的旧访问凭据既不保留旧权限（收窄的权限立即不可再用），也不会因策略更新静默获得
新权限（放开的权限必须续期/重新登录后才生效）——判定依据始终跟随最新的角色权限
集合，而不只看用户身上挂了哪个角色。

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

**幂等投递**：`POST /authorize` 接受可选的 `request_id`（幂等键）。同一调用方对
同一 `request_id` 的重试（无论重试几次、是否并发同时到达）都返回**首次判定的
结论**，且账面上**只记一次**——不因重复投递多记，也不因去重少记。去重键按调用方
作用域（认证用户或 anonymous）隔离，不同调用方使用相同 `request_id` 互不影响；
不带 `request_id` 时保持原有行为（每次判定各记一条）。

## 兼容范围

本轮新增能力对既有行为的影响面：

- 续期失败原因细分：原先并发落败方与重放都返回 `session_reused`（401）；现在
  冲突窗口内的重复提交返回 `concurrent_conflict`（409，可重试），窗口外的重放
  才返回 `session_reused`（401），且复用判定会永久作废会话。依赖旧行为的调用方
  需要区分这两个状态码。
- 角色权限集合变更会使持有该角色用户的旧访问凭据失效（与换角色、禁用同一套
  `token_version` 机制），调用方收到 `unauthenticated` 后续期即可恢复。
- 授权接口新增可选字段 `request_id`，不传时行为与之前完全一致。

## 本地验证

```bash
uv sync                  # 安装依赖
uv run pytest -q -s      # 运行测试（-s 查看关键输入与判定依据日志）
uv run uvicorn app.main:app --reload   # 启动服务
```

测试覆盖：并发续期（16 线程 × 多轮，仅 1 个赢家、落败方全部为可重试撞车）、
冲突窗口外重放判定为复用并永久作废会话、角色权限集合收窄/放开的即时失效与
续期恢复、同一 `request_id` 并发重复投递只记一次账（16 线程 × 10 轮）、
登出/禁用/角色调整的即时失效、提权不静默放行、越权访问、HTTP 端到端链路。
并发用例日志（`pytest -s`）会打印每轮的关键输入（凭据、request_id）与判定
结果分布，便于核对判定依据。

演示数据：用户 `alice/alice-pw`（reader）、`bob/bob-pw`（editor），MFA 密钥分别为
`alice-mfa-secret` / `bob-mfa-secret`（用 `app.auth.totp_code` 生成动态口令）；
资源 `doc-public`、`doc-secret`（confidential）。
