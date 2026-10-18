#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DZMM（https://www.emberloft.xyz）每日签到自动领取。

流程由网页端 /tasks 页面的真实交互逆向而来（抓包记录见 README「逆向记录」），
一共 4 个接口，全部同域、只靠 Cookie 鉴权：

    1. GET  /api/auth/token                会话过期时让服务端续期并回写新 Cookie
    2. GET  /api/trpc/tasks.list           查任务列表，读 daily_checkin 的 claimed / canClaim
    3. POST /api/trpc/tasks.initCheckin    换一次性 checkinToken（入参 fingerprint）
    4. POST /api/trpc/tasks.claim          带 token 领取，返回 rewardAmount

网页端在 initCheckin 之后还有「跳 mirrors 再跳回」一步，那只是给被墙域名准备的中转页；
源码里 mirrors 全部探测失败时会直接调 claim（`if (!i) { await z(n); return }`），
所以这里直接 claim，与网页端等价。

只依赖标准库，无需 pip 安装。

用法：
    python dzmm_checkin.py                       # Cookie 取环境变量 DZMM_COOKIE
    python dzmm_checkin.py --cookie-file cookie.txt
    python dzmm_checkin.py --status              # 只查状态，不领取
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import json
import os
import random
import socket
import ssl
import sys
import time
import urllib.parse
from datetime import datetime

HOST = "www.emberloft.xyz"
BASE = "https://" + HOST
TASK_KEY = "daily_checkin"
SESSION_COOKIE = "sb-rls-auth-token"
SESSION_FILE = "cookies.json"

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)

DEFAULT_HEADERS = {
    "accept": "*/*",
    "accept-language": "zh-CN,zh;q=0.9",
    "accept-encoding": "identity",
    "cache-control": "no-cache",
    "origin": BASE,
    "referer": BASE + "/tasks",
    "sec-fetch-dest": "empty",
    "sec-fetch-mode": "cors",
    "sec-fetch-site": "same-origin",
    "user-agent": UA,
}


def now() -> str:
    return datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")


def log(msg: str = "") -> None:
    print(msg, flush=True)


def set_output(key: str, value) -> None:
    """写 GitHub Actions 的 step output；本地运行时退化成打印。"""
    path = os.environ.get("GITHUB_OUTPUT")
    if path:
        try:
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(f"{key}={value}\n")
            return
        except OSError:
            pass
    log(f"[output] {key}={value}")


# --------------------------------------------------------------------------- cookie


def parse_cookie(raw: str) -> dict:
    """把浏览器里复制的一整行 Cookie 头解析成 dict。"""
    raw = (raw or "").strip()
    if raw.lower().startswith("cookie:"):
        raw = raw.split(":", 1)[1]
    # 兼容多行粘贴（每行一个 name=value）
    raw = "; ".join(line.strip() for line in raw.splitlines() if line.strip())
    cookies = {}
    for chunk in raw.split(";"):
        chunk = chunk.strip()
        if not chunk or "=" not in chunk:
            continue
        name, value = chunk.split("=", 1)
        name = name.strip()
        if name:
            cookies[name] = value.strip()
    return cookies


def seed_digest(cookies: dict) -> str:
    """Cookie 指纹：判断本地缓存 cookies.json 是否源自同一份原始 Cookie。"""
    material = ";".join(f"{k}={cookies[k]}" for k in sorted(cookies))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def load_cached_session(digest: str) -> dict:
    if not os.path.exists(SESSION_FILE):
        return {}
    try:
        with open(SESSION_FILE, encoding="utf-8") as fh:
            payload = json.load(fh)
    except (OSError, ValueError):
        return {}
    if payload.get("seed") != digest:
        log("[cookie] 缓存的会话与当前 Cookie 不是同一份，忽略缓存")
        return {}
    cached = payload.get("cookies") or {}
    return cached if SESSION_COOKIE in cached else {}


def save_cached_session(digest: str, cookies: dict) -> None:
    payload = {"seed": digest, "updated_at": now(), "cookies": cookies}
    try:
        with open(SESSION_FILE, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
        log(f"[cookie] 已刷新会话写入 {SESSION_FILE}（下次运行优先使用，避免旧 refresh_token 被重复消费）")
    except OSError as exc:
        log(f"[cookie] 写 {SESSION_FILE} 失败：{exc}")


def load_cookie(args) -> tuple:
    if args.cookie_file:
        with open(args.cookie_file, encoding="utf-8") as fh:
            seed_raw = fh.read()
        source = args.cookie_file
    else:
        seed_raw = os.environ.get("DZMM_COOKIE") or os.environ.get("COOKIE") or ""
        source = "环境变量 DZMM_COOKIE"
    seed = parse_cookie(seed_raw)
    if SESSION_COOKIE not in seed:
        raise SystemExit(
            f"Cookie 里没有 {SESSION_COOKIE}（来源：{source}）。"
            "请先登录 emberloft.xyz，再从浏览器复制完整 Cookie。"
        )

    digest = seed_digest(seed)
    cached = load_cached_session(digest)
    if cached:
        log(f"[cookie] 复用 {SESSION_FILE} 里的会话（上次刷新过的 {SESSION_COOKIE}）")
        merged = dict(seed)
        merged.update(cached)
        return merged, digest
    log(f"[cookie] 使用原始 Cookie（来源：{source}，共 {len(seed)} 项）")
    return seed, digest


# --------------------------------------------------------------------------- HTTP


class TrpcError(RuntimeError):
    pass


class HttpError(RuntimeError):
    def __init__(self, status, body):
        super().__init__(f"HTTP {status}: {body[:300]}")
        self.status = status
        self.body = body


class CaptchaRequired(RuntimeError):
    """站点反爬挑战：HTTP 418 + {"error":"captcha_required"}，自动化过不去。"""


class Client:
    def __init__(self, cookies: dict, digest: str, verbose: bool = False):
        self.cookies = dict(cookies)
        self.digest = digest
        self.verbose = verbose
        self.refreshed = False
        self._context = ssl.create_default_context()

    # -- 底层 --------------------------------------------------------------

    def _cookie_header(self) -> str:
        return "; ".join(f"{k}={v}" for k, v in self.cookies.items())

    def _absorb_cookies(self, set_cookie_headers) -> None:
        for raw in set_cookie_headers or []:
            pair = raw.split(";", 1)[0]
            if "=" not in pair:
                continue
            name, value = pair.split("=", 1)
            name, value = name.strip(), value.strip()
            if not name:
                continue
            if not value:
                self.cookies.pop(name, None)
                continue
            if name == SESSION_COOKIE and self.cookies.get(name) != value:
                self.refreshed = True
                log("[auth] 服务端下发了新的会话 Cookie")
            self.cookies[name] = value

    def _roundtrip(self, method: str, path: str, payload=None):
        headers = dict(DEFAULT_HEADERS)
        headers["cookie"] = self._cookie_header()
        body = None
        if payload is not None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            headers["content-type"] = "application/json"
            headers["content-length"] = str(len(body))

        conn = http.client.HTTPSConnection(HOST, 443, timeout=30, context=self._context)
        try:
            conn.request(method, path, body=body, headers=headers)
            resp = conn.getresponse()
            data = resp.read()
            status = resp.status
            encoding = (resp.getheader("content-encoding") or "").lower()
            if encoding == "gzip" and data:
                import gzip

                data = gzip.decompress(data)
            elif encoding == "deflate" and data:
                import zlib

                try:
                    data = zlib.decompress(data)
                except zlib.error:
                    data = zlib.decompress(data, -zlib.MAX_WBITS)
            self._absorb_cookies(resp.headers.get_all("Set-Cookie"))
        finally:
            conn.close()

        if self.verbose:
            log(f"    << {method} {path} -> {status} ({len(data)}b)")

        if status == 418 or b"captcha_required" in data:
            # 站点反爬层：整个域名（连首页）都会被挡，和 Cookie 是否有效无关
            raise CaptchaRequired(f"HTTP {status} · {data[:120].decode('utf-8', 'replace')}")

        return status, data

    def request(self, method: str, path: str, payload=None, retry: int = 3,
                allow_auth_retry: bool = True):
        last_error = None
        for attempt in range(1, retry + 1):
            try:
                status, data = self._roundtrip(method, path, payload)
            except (OSError, socket.error, ssl.SSLError, http.client.HTTPException) as exc:
                last_error = exc
                if attempt < retry:
                    time.sleep(1.5 * attempt + random.random())
                    continue
                raise

            if status >= 500 and attempt < retry:
                last_error = HttpError(status, data.decode("utf-8", "replace"))
                time.sleep(1.5 * attempt + random.random())
                continue

            if status in (401, 403) and allow_auth_retry and self.refresh_session():
                # 与网页端一致：401 时先让服务端续期一次，再重放原请求
                return self.request(
                    method, path, payload, retry=retry, allow_auth_retry=False
                )
            return status, data
        raise last_error or RuntimeError("request failed")  # pragma: no cover

    # -- 会话 --------------------------------------------------------------

    def refresh_session(self) -> bool:
        """GET /api/auth/token：服务端用 Cookie 里的 refresh_token 续期并回写新 Cookie。"""
        log("[auth] 会话检查 / 续期 …")
        try:
            status, data = self._roundtrip("GET", "/api/auth/token")
        except (OSError, socket.error, http.client.HTTPException) as exc:
            log(f"[auth] 请求失败：{exc}")
            return False
        if status != 200:
            log(f"[auth] 失败：HTTP {status} {data.decode('utf-8', 'replace')[:200]}")
            return False
        try:
            payload = json.loads(data.decode("utf-8"))
        except ValueError:
            log("[auth] 返回的不是 JSON")
            return False
        expires_at = payload.get("expires_at")
        if expires_at:
            left = int(expires_at) - int(time.time())
            if left <= 60:
                # 服务端把 Cookie 里的 token 原样回显时也会走到这里，
                # 真正的判定交给后面的 tasks.list（401 才说明会话真的废了）
                log(f"[auth] 返回的 access_token 已过期（{left // 60} 分钟），会话可能需要重新登录")
            else:
                log(f"[auth] OK，access_token 剩余 {left // 60} 分钟")
        else:
            log("[auth] OK")
        return True

    # -- tRPC --------------------------------------------------------------

    @staticmethod
    def _unwrap(payload):
        item = payload[0] if isinstance(payload, list) and payload else payload
        if isinstance(item, dict) and item.get("error"):
            err = item["error"]
            detail = err.get("json") if isinstance(err, dict) else None
            message = detail.get("message") if isinstance(detail, dict) else None
            code = None
            if isinstance(detail, dict):
                code = (detail.get("data") or {}).get("code")
            raise TrpcError(f"{message or err}（code={code}）")
        if not isinstance(item, dict) or "result" not in item:
            raise TrpcError(f"意外的响应：{str(payload)[:300]}")
        data = item["result"].get("data") or {}
        return data.get("json", data)

    def query(self, procedure: str) -> dict:
        packed = {"0": {"json": None, "meta": {"values": ["undefined"]}}}
        path = f"/api/trpc/{procedure}?batch=1&input=" + urllib.parse.quote(
            json.dumps(packed, separators=(",", ":"))
        )
        status, data = self.request("GET", path)
        if status != 200:
            raise HttpError(status, data.decode("utf-8", "replace"))
        return self._unwrap(json.loads(data.decode("utf-8")))

    def mutation(self, procedure: str, payload: dict) -> dict:
        body = {"0": {"json": payload}}
        status, data = self.request("POST", f"/api/trpc/{procedure}?batch=1", body)
        if status != 200:
            raise HttpError(status, data.decode("utf-8", "replace"))
        return self._unwrap(json.loads(data.decode("utf-8")))

    # -- 业务 --------------------------------------------------------------

    def find_task(self, key: str) -> dict:
        tasks = self.query("tasks.list").get("tasks") or []
        for task in tasks:
            if task.get("key") == key:
                return task
        raise TrpcError(f"任务列表里没有 {key}")

    def balance(self) -> dict:
        try:
            return self.query("credits.getBalance")
        except (TrpcError, HttpError, ValueError):
            return {}


def fingerprint_of(cookies: dict) -> str:
    """网页端用浏览器指纹哈希，服务端只当作风控标记；任意稳定的 32 位十六进制都可用。"""
    uid = ""
    raw = cookies.get(SESSION_COOKIE, "")
    if raw.startswith("base64-"):
        try:
            padded = raw[len("base64-"):].replace("-", "+").replace("_", "/")
            padded += "=" * (-len(padded) % 4)
            uid = json.loads(base64.b64decode(padded)).get("user", {}).get("id", "")
        except Exception:  # noqa: BLE001 - 解不出来也不影响签到
            uid = ""
    material = f"dzmm-web-fingerprint-v1:{uid or 'anonymous'}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]


# --------------------------------------------------------------------------- flow


def describe(task: dict) -> str:
    return (
        f"{task.get('title')} | 奖励 {task.get('reward')} | 状态 {task.get('status')}"
        f" | claimed={task.get('claimed')} canClaim={task.get('canClaim')}"
        f" | 周期 {task.get('periodRef')}"
    )


def print_balance(client: Client) -> None:
    bal = client.balance()
    if bal:
        log(
            f"[balance] 积分 {bal.get('credit')} + 限时 {bal.get('bonusCredit')}"
            f" = {bal.get('total')}"
        )


def run(args, holder: dict) -> int:
    log("=" * 62)
    log(f"DZMM 每日签到 · {now()}")
    log("=" * 62)

    cookies, digest = load_cookie(args)
    client = Client(cookies, digest, verbose=args.verbose)
    holder["client"] = client

    if getattr(args, "export_cookie", False):
        # 把「原始 Cookie + 本地缓存续期后」的当前会话打印出来，方便更新 Secret
        log("; ".join(f"{k}={v}" for k, v in cookies.items()))
        set_output("checked_in", "false")
        set_output("reason", "export_cookie")
        return 0

    # 1) 确认 / 刷新会话（Cookie 里的 access_token 只有 1 小时）
    try:
        session_ok = client.refresh_session()
    except CaptchaRequired as exc:
        log(f"[fail] 站点要求人机验证：{exc}")
        log("[fail] 这是站点的反爬/风控挑战（整个域名都会 418），不是 Cookie 失效；"
            "过一阵重试，或换出口 IP（自建 runner / 代理）")
        set_output("checked_in", "false")
        set_output("reason", "captcha_required")
        return 3
    if not session_ok:
        log("[auth] 会话无效：Cookie 已失效，请重新登录 emberloft.xyz 后更新 Cookie")
        set_output("checked_in", "false")
        set_output("reason", "cookie_invalid")
        return 2

    # 2) 当前状态
    task = client.find_task(TASK_KEY)
    log(f"[task] {describe(task)}")

    if args.status:
        print_balance(client)
        set_output("checked_in", "false")
        set_output("reason", "status_only")
        return 0

    if task.get("claimed"):
        log("[skip] 今天已经签到过，无需重复领取")
        print_balance(client)
        set_output("checked_in", "false")
        set_output("reason", "already_claimed")
        return 0

    if not task.get("canClaim"):
        log(f"[skip] 当前不可领取（status={task.get('status')}）")
        set_output("checked_in", "false")
        set_output("reason", "not_claimable")
        return 0

    # 3) 换一次性 checkinToken（有效期很短，拿到就立刻用）
    init = client.mutation("tasks.initCheckin", {"fingerprint": fingerprint_of(client.cookies)})
    if init.get("captchaRequired"):
        log("[fail] 服务端要求人机验证（captchaRequired=true），脚本无法继续")
        set_output("checked_in", "false")
        set_output("reason", "captcha_required")
        return 3

    token = init.get("token")
    if not token:
        log(f"[fail] initCheckin 未返回 token：{init}")
        set_output("checked_in", "false")
        set_output("reason", "no_token")
        return 3
    log(f"[init] 已取得 checkinToken（{len(token)} 字符），mirrors={init.get('mirrors')}")

    # 4) 领取
    try:
        result = client.mutation("tasks.claim", {"taskKey": TASK_KEY, "checkinToken": token})
    except TrpcError as exc:
        # 网络异常时请求可能已被服务端处理，先复核再决定是否判失败
        log(f"[claim] 领取请求异常：{exc}")
        if client.find_task(TASK_KEY).get("claimed"):
            log("[claim] 复核发现其实已经领取成功")
            result = {"success": True, "rewardAmount": task.get("reward")}
        else:
            raise

    if not result.get("success"):
        log(f"[fail] 领取未成功：{result}")
        set_output("checked_in", "false")
        set_output("reason", "claim_failed")
        return 4

    reward = result.get("rewardAmount", task.get("reward"))
    log(f"[claim] 领取成功 +{reward} 积分（orderId={result.get('orderId')}）")

    # 5) 复核
    after = client.find_task(TASK_KEY)
    log(f"[task] {describe(after)}")
    if not after.get("claimed"):
        log("[warn] 接口返回成功，但任务仍未标记已领取，请手动到网页确认")
        set_output("checked_in", "false")
        set_output("reason", "verify_failed")
        return 5

    print_balance(client)
    set_output("checked_in", "true")
    set_output("reward", reward)
    set_output("reason", "ok")
    log("[done] 签到完成")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="DZMM 每日签到自动领取（零依赖）")
    parser.add_argument("--cookie-file", help="从文件读取 Cookie（默认读环境变量 DZMM_COOKIE）")
    parser.add_argument("--status", action="store_true", help="只查询状态，不领取")
    parser.add_argument("--export-cookie", action="store_true",
                        help="打印当前会话的 Cookie（含本地缓存续期后的），用于更新 Secret")
    parser.add_argument("--no-cache", action="store_true", help="忽略并重建本地会话缓存")
    parser.add_argument("--verbose", action="store_true", help="打印每个请求")
    args = parser.parse_args()

    if args.no_cache and os.path.exists(SESSION_FILE):
        os.remove(SESSION_FILE)
        log(f"[cookie] 已删除 {SESSION_FILE}")

    holder: dict = {}
    try:
        return run(args, holder)
    except SystemExit:
        raise
    except HttpError as exc:
        if exc.status in (401, 403):
            log(f"[auth] 服务端拒绝：Cookie 已失效（HTTP {exc.status}），请重新登录后更新 Cookie")
            set_output("checked_in", "false")
            set_output("reason", "cookie_invalid")
            return 2
        log(f"[error] {type(exc).__name__}: {exc}")
        return 1
    except CaptchaRequired as exc:
        log(f"[fail] 站点要求人机验证：{exc}")
        log("[fail] 反爬挑战（HTTP 418）不是 Cookie 问题，过一阵重试或换出口 IP")
        set_output("checked_in", "false")
        set_output("reason", "captcha_required")
        return 3
    except Exception as exc:  # noqa: BLE001 - 统一出口，便于 Actions 里读日志
        log(f"[error] {type(exc).__name__}: {exc}")
        return 1
    finally:
        client = holder.get("client")
        if client is not None and client.refreshed:
            save_cached_session(client.digest, client.cookies)


if __name__ == "__main__":
    sys.exit(main())
