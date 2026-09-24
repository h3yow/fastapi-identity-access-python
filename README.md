# 本地身份与访问控制服务（FastAPI）

一套可在本地直接运行、结论**一致且可解释**的身份与访问控制能力：
用进程内存储模拟身份源、凭据与审计，覆盖 **MFA 登录 → 短期访问凭据 +
可轮换长期会话（刷新令牌）→ 基于角色与资源属性的授权判定 → 即时撤销/变更**
全链路，并对并发续期、凭据重放、权限撤销与越权访问给出稳定、可区分的结论。

---

## 1. 运行

```bash
uv sync                       # 安装依赖（含 pytest）
uv run uvicorn main:app --reload
# 或
uv run python -m uvicorn main:app --port 8000
```

- 交互式文档：<http://127.0.0.1:8000/docs>
- 健康检查：`GET /health`

生成当前演示 TOTP 验证码：

```bash
uv run python scripts/totp_now.py
```

> `/auth/login/begin` 的响应里也带 `dev_totp_hint` 字段（**仅本地演示**）。

---

## 2. 身份模型

| 对象 | 说明 |
| --- | --- |
| `User` | `id / username / password_hash(PBKDF2) / roles / enabled / mfa_secret / roles_version` |
| `Session` | 一次登录建立的**会话家族**（`family_id`），有绝对过期时间与撤销状态 |
| `RefreshToken` | 长期、**一次性**刷新令牌，属于某个会话家族，携带轮换链 `replaced_by` |
| `AccessTokenRecord` | 短期访问凭据（不透明随机串），签发时**快照**了 `roles / roles_version / policy_version` |
| `Policy` | 主体（用户/角色/属主）× 动作 × 资源属主 × 资源标签 → allow/deny |
| `Resource` | `id / owner / tags / exists`（软删除，存在性语义明确） |
| `Decision` | 一次授权判定的权威结论，以 `request_id` 幂等记账 |

种子账号（口令见下，TOTP 共享演示密钥 `JBSWY3DPEHPK3PXP`）：

| 用户名 | 口令 | 角色 |
| --- | --- | --- |
| `admin` | `admin-pw` | `admin`（通配） |
| `alice` | `alice-pw` | `member` |
| `bob` | `bob-pw` | `member` |

种子资源：`doc-alice-1{doc}`、`doc-alice-secret{doc,secret}`、`doc-bob-1{doc}`。

种子策略：

1. `p-owner-read`：**属主**可读自己任意资源；
2. `p-admin-all`：`admin` 角色对一切 `*` allow；
3. `p-member-read-doc`：`member` 可读带 `doc` 标签的资源；
4. `p-deny-secret`：`member` 对带 `secret` 标签的资源 **显式 deny**。

多策略命中采用 **deny-overrides（显式拒绝优先）**。因此 alice 虽是
`doc-alice-secret` 的属主（命中 owner allow），但同时命中 member deny，结论仍为拒绝。

---

## 3. 凭据与会话生命周期

### 3.1 两段式 MFA 登录

```text
POST /auth/login/begin      {username,password}
    -> 200 {challenge_id, dev_totp_hint}
       失败：invalid_credentials（用户不存在与口令错误同因，防枚举）
             account_disabled
POST /auth/login/complete   {challenge_id,mfa_code}
    -> 200 {access_token, refresh_token, access_expires_in, session_id}
       失败：mfa_invalid / mfa_challenge_expired（挑战一次性、可过期）
```

登录成功建立一个会话家族，并签发**首对**访问凭据 + 刷新令牌。

### 3.2 访问凭据（短期）

- 默认 TTL 60s（见 `app/settings.py`），不透明随机串。
- 每次使用都回到身份源做**即时校验**，而不是只信令牌内容：
  - 自身：无法识别 / 已撤销 / 已过期 →
    `access_token_invalid` / `access_token_expired`；
  - 会话已撤销（登出、重放连带）→ `session_revoked`；
  - 账号被禁用 → `account_disabled`；
  - 角色版本不一致 → `role_revision_stale`；
  - 策略版本不一致 → `policy_revision_stale`。

### 3.3 刷新令牌（长期、可轮换、单次使用）

```text
POST /auth/refresh  {refresh_token}
    -> 200 一对新的 access_token + refresh_token（旧令牌即作废）
```

状态机（失败原因严格可区分）：

```text
ACTIVE ──轮换──> CONSUMED(replaced_by=新令牌)
                   ├─ 并发窗口内再次出现           -> 409 refresh_concurrent（输家）
                   └─ 窗口外 / 后继异常再次出现     -> 401 refresh_reuse_detected
ACTIVE 直接并发轮换：会话级互斥锁串行，只有 1 个赢家，其余 refresh_concurrent
已撤销 -> refresh_token_revoked / session_revoked
已过期 -> refresh_expired
```

关键安全语义：

- **单次使用成立**：任何刷新令牌轮换后立即 `CONSUMED`，不可二次成功使用。
- **并发续期不产生两个会话**：同一 `session_id` 一把互斥锁，N 个并发请求恰好 1 个成功。
- **重放检测整族作废**：窗口外的旧令牌再现被视为窃取重放，
  立即撤销该 `family_id` 的全部会话与令牌（含攻击者刚拿到的新令牌）。
- **并发 vs 重放可区分**：窗口内且后继令牌仍健康 → `refresh_concurrent`（409），
  此时**不会误杀赢家**；窗口外才是 `refresh_reuse_detected`（401）。

### 3.4 失效与权限变更即时生效

| 事件 | 入口 | 效果 |
| --- | --- | --- |
| 主动登出 | `POST /auth/logout` | 会话 + 该会话全部未过期访问/刷新凭据立即撤销 |
| 账号禁用 | `POST /admin/users/{u}/enabled {enabled:false}` | 该用户全部会话与凭据立即撤销，访问返回 `account_disabled` |
| 角色调整 | `POST /admin/users/{u}/roles` | `roles_version+1`，旧凭据立刻 `role_revision_stale`；续期后按新角色判定 |
| 策略更新 | 任意策略写操作 | 全局 `policy_version+1`，旧凭据立刻 `policy_revision_stale`，**拒绝而非静默放行/降级** |

> 角色/策略调整不“静默改权”：旧凭据被要求重新续期，新凭据携带最新版本快照，
> 从机制上杜绝“凭据还活着却沿用旧权限”或“策略收紧后仍被放行”。

---

## 4. 授权判定规则

`GET /resources/{id}?action=read`，凭据放在 `Authorization: Bearer <access_token>`，
可带 `X-Request-Id` 标识同一逻辑请求。判定顺序固定，返回四类语义明确的结果：

| 顺序 | 情况 | reason 前缀 | HTTP |
| --- | --- | --- | --- |
| 1 | 未认证（无/无效/过期/撤销/版本陈旧凭据） | `unauthenticated:<具体错误码>` | 401（账号禁用为 403） |
| 2 | 目标资源不存在/已删除 | `resource_not_found` | 404 |
| 3 | 已认证但未授权（无允许策略或命中 deny） | `forbidden:<依据>` | 403 |
| 4 | 允许 | `allow:<命中的策略与版本>` | 200 |

响应同时给出 `billed`（是否计费/记账）与可读的**判定依据**（命中的策略 id、版本）。

**一致性与不重复记账**：以 `request_id` 幂等。同一请求的并发/重试只会产生**一条**
审计记录、计数器只增加一次；所有并发调用拿到同一份权威结论。判定与记账在同一存储
串行化区域完成，避免“部分授权”或“重复记账”。

---

## 5. 本地验证方法

```bash
uv run pytest -q                 # 全部单测（含并发线程用例）
uv run pytest tests/test_authentication.py -q
uv run pytest tests/test_authz.py -q
uv run pytest tests/test_api.py -q
```

测试覆盖（结论稳定、失败原因可区分；日志打印关键输入与判定依据）：

- `test_authentication.py`
  - MFA 成功/错码/过期/挑战一次性；口令错误与用户不存在同因；
  - 刷新轮换单次使用、窗口外重放→整族撤销、窗口内并发→仅一赢家；
  - **8 线程并发续期恰好 1 个成功**，其余 `refresh_concurrent`，活动会话恰 1 个；
  - 已撤销 vs 已过期原因可区分。
- `test_authz.py`
  - 四种结果语义可区分；属主/角色/deny-overrides；
  - 禁用、登出后未过期凭据立即失效；角色变更与策略更新即时生效且需续期；
  - **16 线程同一 request_id 结论一致且只计费一次**。
- `test_api.py`
  - HTTP 端到端：错误码、越权 403、404、401；刷新重放连带撤销；禁用即时拒绝；
    登出后凭据作废；并发同 request_id 仅记账一次。

测试用虚拟时钟（`tests/conftest.py` 的 `Clock`）精确推进过期与并发窗口，
因此并发结论不依赖真实时序，稳定可复现。

---

## 6. 目录结构

```text
app/
  errors.py             # 稳定错误码 ErrorCode + DomainError
  models.py             # User/Session/RefreshToken/AccessToken/Policy/Resource/Decision
  settings.py           # TTL 与并发窗口等可调参数
  security.py           # PBKDF2 口令、随机令牌、RFC6238 TOTP
  storage.py            # 线程安全内存存储 + 会话级互斥锁 + 幂等审计表
  audit.py              # request_id 幂等记账/计费
  services/
    authentication.py   # 登录/MFA/刷新状态机/即时校验/登出/管理操作
    authz.py            # 四类结果判定、deny-overrides、幂等决策
    admin.py            # 策略/资源管理（推动 policy_version）
    seed.py             # 本地种子身份/资源/策略
  api/                  # HTTP 路由与依赖
  app.py                # 应用装配与统一错误处理
scripts/totp_now.py     # 生成当前演示 TOTP
tests/                  # 认证 / 授权 / HTTP 端到端（含并发）用例
```
