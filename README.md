# DZMM 每日签到（GitHub Actions）

用 Cookie 登录 [www.emberloft.xyz](https://www.emberloft.xyz/)，每天北京时间 **09:00**
自动打开 `/tasks` 页面的「每日签到」任务并点「领取」，拿到当日积分奖励。

写法参考 [fmdxx1991/wnflb-checkin](https://github.com/fmdxx1991/wnflb-checkin)：
Python 脚本 + GitHub Actions + Cookie 走 Secrets。

> 站点用的是一套 Next.js + tRPC 的接口，不是 Discuz，所以没有 `formhash` 之类的表单，
> 直接按浏览器真实发出的 4 个请求回放即可，见下面的「逆向记录」。

---

## 快速开始

1. **Fork / 上传** 本仓库（建议设为 **Private**：Cookie 等价于账号登录态）。
2. 在浏览器登录 `https://www.emberloft.xyz/`，F12 → Network → 任意请求 → 复制整行
   `Cookie` 请求头（必须包含 `sb-rls-auth-token=...`）。
3. 仓库 `Settings → Secrets and variables → Actions → New repository secret`：
   - `DZMM_COOKIE`：上一步复制的整行 Cookie（**必填**）
   - 本目录里的 `cookie.txt` 存的是刚续期过的最新会话，也可以直接把它整行内容粘进去
     （`cookie.txt` 已在 `.gitignore` 里，不会被提交）
4. `Actions` → `DZMM 每日签到` → `Run workflow` 手动跑一次确认。
5. 之后每天 UTC 01:00（北京时间 09:00）自动执行，也可以在 Actions 页面手动触发。

> GitHub 的 `schedule` 是 UTC 时间，且高峰期可能延迟几分钟到几十分钟；
> 站点在 UTC 00:00（北京 08:00）重置，所以 09:00 触发不会撞上重置边界。

---

## 本地运行

```bash
python dzmm_checkin.py --cookie-file cookie.txt     # 用文件里的 Cookie
python dzmm_checkin.py --status                     # 只看状态，不领取
python dzmm_checkin.py --export-cookie              # 打印当前最新 Cookie（用于更新 Secret）
DZMM_COOKIE="sb-rls-auth-token=..." python dzmm_checkin.py
```

Windows 可直接双击 `test_local.bat`（读同目录的 `cookie.txt`）。
脚本只用标准库，**不需要 pip install**，Python 3.9+ 即可。

退出码：`0` 成功/已领过 `1` 异常 `2` Cookie 失效 `3` 需要验证码 `4` 领取失败 `5` 状态复核失败。

---

## 逆向记录

网页端「领取」按钮实际发出的请求（完整、已脱敏的交互记录见
[`docs/trace.json`](docs/trace.json)）：

| # | 方法 | 路径 | 作用 |
|---|------|------|------|
| 1 | `GET` | `/api/auth/token` | 会话续期；Cookie 里的 `access_token` 只有 1 小时，服务端会用 `refresh_token` 换新 |
| 2 | `GET` | `/api/trpc/tasks.list?batch=1&input=...` | 任务列表，读 `daily_checkin` 的 `claimed` / `canClaim` / `periodRef` |
| 3 | `POST` | `/api/trpc/tasks.initCheckin?batch=1` | 入参 `{"fingerprint":"<32位hex>"}`，返回一次性 `token`（约 20 分钟有效）与 `mirrors` |
| 4 | `POST` | `/api/trpc/tasks.claim?batch=1` | 入参 `{"taskKey":"daily_checkin","checkinToken":"<token>"}`，返回 `rewardAmount` |

请求体是 tRPC + superjson 的批处理格式，所有参数都包一层：

```jsonc
// 查询类（void 入参）：GET ?batch=1&input={"0":{"json":null,"meta":{"values":["undefined"]}}}
// 变更类：POST body
{"0":{"json":{"taskKey":"daily_checkin","checkinToken":"eyJ..."}}}
```

响应同样包一层，成功是 `[{"result":{"data":{"json":{...}}}}]`，
失败是 `[{"error":{"json":{"message":"UNAUTHORIZED","code":-32001,...}}}]`。

真实领取结果：

```json
[{"result":{"data":{"json":{"success":true,"orderId":"task-daily_checkin-<hash>-2026-10-18","rewardAmount":5}}}}]
```

### 关于 `mirrors`

`initCheckin` 会顺便返回 `mirrors`（`dzmm-home.github.io/dzmm-addr/`、`dzmm.pages.dev/`
这类中转页）。网页端的逻辑是：拿 token → 探测 mirrors → **跳过去再跳回来**完成签到；
但源码里 mirrors 全部探测失败时，会直接调 `tasks.claim`（`if (!i) { await z(n); return }`）。
也就是说 mirrors 只是给被墙域名准备的中转，领取本身不依赖它，
所以脚本直接 `initCheckin → claim`，与网页端等价（已实测成功）。

### 关于 `fingerprint`

网页端传的是一个浏览器指纹哈希（用 canvas/UA 等算出来的 32 位 hex）。
服务端只把它当风控标记，不校验具体内容，脚本用「用户 ID 的 sha256 前 32 位」保持稳定即可。

---

## Cookie 与续期（已实测）

- Cookie 里最关键的是 `sb-rls-auth-token`，它是 Supabase 会话（`base64-` + JSON），
  内含 `access_token`、`refresh_token`、`expires_at`。
- `access_token` 只有 **1 小时**。过期后请求 `GET /api/auth/token`，服务端会用
  `refresh_token` 换一份新会话，并通过 `Set-Cookie` 下发新的 `sb-rls-auth-token`。
- **`refresh_token` 每次续期都会轮换**（实测：`3blbmss…` → `tmixm5b…`），旧的那份随即作废。
  所以脚本会把新会话写进 `cookies.json`，由 Actions 缓存带给下一次运行——
  **这个缓存就是「会话接力棒」，不要当成可有可无的优化**。
- `cookies.json` 里记录了「它派生自哪份原始 Cookie」的指纹：换了新 Cookie 会自动弃用旧缓存，
  不会出现新旧会话打架。
- 想知道当前最新的 Cookie（比如缓存里的会话已经滚了好几代，你要同步更新 Secret）：
  ```bash
  python dzmm_checkin.py --cookie-file cookie.txt --export-cookie
  ```
  打印出来的那一整行就是当前可用的 Cookie。
- **浏览器和 Actions 别共用同一条会话**：`refresh_token` 轮换后只有一份有效，
  两边各自续期会互相把对方挤下线。推荐做法：用无痕窗口登录 → 复制 Cookie → **关掉无痕窗口**，
  这条会话就只归 Actions 用；接着用你自己的浏览器重新登录不受影响。
- 如果日志里出现 `[auth] 服务端拒绝：Cookie 已失效` / `cookie_invalid`，
  说明 `refresh_token` 已被别处用掉或已失效：重新登录复制 Cookie，更新 `DZMM_COOKIE` 即可
  （脚本发现 Cookie 换了会自动丢弃旧缓存）。
- 缓存连续 7 天没被访问会被 GitHub 清理；如果一直跑得好好的突然报 Cookie 失效，
  优先怀疑缓存丢了，按上一条重新复制 Cookie。

---

## 注意

- **公开仓库千万不要用**：Cookie 就是账号登录态，任何人都能读 Actions 日志和环境变量以外的缓存。
  本项目默认已把 `cookie.txt`、`cookies.json` 写进 `.gitignore`。
- 站点有反爬层，会按 IP 信誉挑战：整个域名（连首页）都可能返回
  `418 {"error":"captcha_required","location":"/__captcha/"}`。脚本把这种情况单独识别成
  **退出码 3 / `captcha_required`**，它 **不是 Cookie 失效**，过一阵重试通常就恢复了；
  GitHub 机房 IP 更容易被挑战，长期遇到就换自建 runner 或加代理。
- `initCheckin` 返回 `captchaRequired: true` 时同样是退出码 3，原因一样。
- 站点改版（接口路径、任务 key 从 `daily_checkin` 改名、多一步校验）会导致脚本失效，
  届时重新抓一次 `/tasks` 页面的网络请求，对照 `docs/trace.json` 改路径即可。
- 签到奖励是「限时积分」（30 天有效），每天只能领一次；网页端和 Telegram 共用同一次签到，
  脚本发现当天已领过会直接跳过，不会重复请求领取接口。
- **网页端突然要重新登录是正常的**：同一条会话的 `refresh_token` 被脚本用掉并轮换后，
  浏览器手里那份就过期了，重新登录一次即可（重新登录会换新链，记得同步更新 `DZMM_COOKIE`）。

---

## 文件

```
dzmm_checkin.py               # 主脚本（零依赖）
test_local.bat                # Windows 本地一键运行
cookie.txt                    # 本地 Cookie（已 gitignore）
.github/workflows/checkin.yml # 每天 09:00（UTC 01:00）执行
docs/trace.json               # 本次真实领取过程的脱敏交互记录
```
