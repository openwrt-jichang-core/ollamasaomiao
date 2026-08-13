import ipaddress
import json
import logging
import os
import re
import secrets
import socket
import threading
import time
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse

import aiofiles
import requests
from fastapi import Depends, FastAPI, HTTPException, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from auth import AuthManager
from ws_manager import capture_running_loop, manager as ws_manager, push_from_thread
from scanner import (
    ScanState,
    quick_test,
    refresh_custom_core_cases,
    refresh_custom_language_cases,
    run_advanced_tests,
    run_headless_tests_only,
    set_headless_tests_enabled,
    set_test_categories_enabled,
    start_scan_thread,
)

DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
HOSTS_FILE = DATA_DIR / "hosts.json"
RESULTS_FILE = DATA_DIR / "scan_results.json"
LEADERBOARD_FILE = DATA_DIR / "leaderboard.json"
PING_STATUS_FILE = DATA_DIR / "ping_status.json"
AUDIT_LOG_FILE = DATA_DIR / "audit.json"
AUDIT_LOG_MAX_ENTRIES = 1000
SETTINGS_FILE = DATA_DIR / "settings.json"

# 历史趋势数据：只允许追加/读取/清理这一个固定路径，绝不接受任何用户输入拼出的路径，
# 避免被人通过参数注入去读写这个目录之外的任意文件（比如尝试路径穿越读 /etc/passwd 之类）。
HISTORY_FILE = DATA_DIR / "history.jsonl"
HISTORY_MAX_SIZE_BYTES_HARD_CAP = 200 * 1024 * 1024  # 200MB 硬上限，无论设置里怎么配都不会超过这个

# 归档：把"当前工作区"(hosts.json + leaderboard.json + scan_results.json)整体存一份快照进这个文件，
# 然后清空当前工作区，让扫描台可以重新开始而不丢历史数据。加新主机时会检查所有归档，防止重复添加。
ARCHIVES_FILE = DATA_DIR / "archives.json"

# 地球可视化用：IP归属地查询结果本地缓存(31天有效)，避免每次打开地球界面都重新调用外部接口。
GEOIP_CACHE_FILE = DATA_DIR / "geoip_cache.json"

DEFAULT_SETTINGS = {
    "schedule": {
        "enabled": False,
        "time": "09:00",       # 24小时制 HH:MM，本地时区（容器时区）
        "concurrency": 3,
        "model_concurrency": 4,
        "enable_core": True,
        "enable_control": True,
        "enable_language": True,
        "enable_headless": False,  # 无头浏览器测试比较重，定时扫描默认也不跑
    },
    "notify": {
        "wecom": {"enabled": False, "webhook_url": ""},
        "telegram": {"enabled": False, "bot_token": "", "chat_id": ""},
        "bark": {"enabled": False, "key": "", "server": "https://api.day.app"},
        "email": {
            "enabled": False, "smtp_host": "", "smtp_port": 587,
            "username": "", "password": "", "from_addr": "", "to_addr": "",
            "use_tls": True,
        },
    },
    "history": {
        "retention_days": 180,     # 超过这个天数的记录会被定期清理自动删除
        "max_size_mb": 50,         # history.jsonl 超过这个大小时，从最旧的记录开始删，直到降到限制以下
        "auto_cleanup_enabled": True,
    },
    "share": {
        "enabled": False,
        "tokens": [],   # [{"token": str, "label": str, "created_at": iso str, "expires_at": iso str|None}]
    },
    "metrics": {
        "enabled": False,
        "token": "",    # Prometheus 抓取用的 token，通过 URL query 或 Authorization: Bearer 传入
    },
    "custom_language_tests": [],  # [{"name","prompt","rules":[...]}]，只做纯文本规则判定，不执行代码
    "custom_core_tests": [],      # [{"name","prompt","harness","expected"}]，会在沙箱子进程执行代码，新增需二次输入密码确认
    "company": {"name": "", "address": "", "lat": None, "lon": None},  # 地球可视化里"公司地址"锚点
    "address_discovery": {
        # 定期访问一个网页(自己的域名/局域网地址都行)，从返回的HTML文本里提取 ip:port，
        # 自动加进主机列表——用于"内网地址会变/通过网站中转上报当前地址"这种场景。
        "enabled": False,
        "url": "",
        "interval_minutes": 30,
        "group": "",
        "tags": [],
        "last_run_at": None,
        "last_status": None,     # "ok" | "cf_blocked" | "error"
        "last_message": "",
        "last_found": [],        # 最近一次提取到的地址列表
    },
}


def _load_json_file(path: Path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text())
    except Exception:
        return default


def _save_json_file(path: Path, data):
    """原子写：先写临时文件再 os.replace 覆盖，避免容器被强杀在写入中途导致 JSON 半写坏文件。"""
    try:
        tmp = path.with_name(f".{path.name}.tmp.{os.getpid()}.{threading.get_ident()}")
        tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False))
        os.replace(tmp, path)
    except Exception:
        pass


# 各持久化文件各自一把锁：保护"读整个文件 -> 内存改 -> 整体写回"这种非原子的
# read-modify-write 操作，避免并发请求互相覆盖导致更新丢失。
_hosts_lock = threading.Lock()
_leaderboard_lock = threading.Lock()
_ping_lock = threading.Lock()
_results_lock = threading.Lock()
_audit_lock = threading.Lock()
_archives_lock = threading.Lock()
_geoip_lock = threading.Lock()
_settings_lock = threading.Lock()
_history_lock = threading.Lock()

SESSION_COOKIE = "scanner_session"
# 部署在 Coolify/反代之后走 HTTPS 时应保持默认 true；纯本地 http 调试可设 COOKIE_SECURE=false
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "true").lower() != "false"

app = FastAPI(title="Ollama Cluster Scanner")
SCAN_LOG_FILE = DATA_DIR / "scan_log.jsonl"
state = ScanState(log_file=SCAN_LOG_FILE)  # 全局唯一主状态，日志落盘，重启/刷新不丢
state.set_broadcast_callback(push_from_thread)  # 扫描线程产生的每条日志/状态变化都经这里推给 WS 客户端
auth_mgr = AuthManager(DATA_DIR)

# ---------------------------------------------------------------------------
# 简单的进程内限流：防止接口被刷（爆破登录之外的一般性滥用/流量攻击）
# ---------------------------------------------------------------------------
RATE_LIMIT_WINDOW = 60
RATE_LIMIT_MAX_REQUESTS = 180
_rate_log = defaultdict(deque)
_rate_lock = threading.Lock()
_rate_cleanup_counter = 0
_RATE_CLEANUP_EVERY = 500  # 每处理这么多个请求，顺带清一次已经空掉的 IP 队列


def get_client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    global _rate_cleanup_counter
    ip = get_client_ip(request)
    now = time.time()
    with _rate_lock:
        dq = _rate_log[ip]
        while dq and now - dq[0] > RATE_LIMIT_WINDOW:
            dq.popleft()
        if len(dq) >= RATE_LIMIT_MAX_REQUESTS:
            return JSONResponse({"detail": "请求过于频繁，请稍后再试"}, status_code=429)
        dq.append(now)

        _rate_cleanup_counter += 1
        if _rate_cleanup_counter >= _RATE_CLEANUP_EVERY:
            _rate_cleanup_counter = 0
            stale_ips = [k for k, v in _rate_log.items() if not v]
            for k in stale_ips:
                del _rate_log[k]
    return await call_next(request)


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' https://fonts.googleapis.com 'unsafe-inline'; "
        "font-src https://fonts.gstatic.com; "
        "script-src 'self'; "
        "connect-src 'self'; "
        "img-src 'self' data:; "
        "frame-ancestors 'none'"
    )
    return response


@app.on_event("startup")
async def _capture_loop_on_startup():
    # 扫描跑在普通 threading 线程里，要往 WS 广播必须先记住这个主事件循环，
    # 否则 asyncio.run_coroutine_threadsafe 无处可投递。
    capture_running_loop()


# ---------------------------------------------------------------------------
# 鉴权：密码登录 + 会话 Cookie + 失败次数指数退避锁定
# ---------------------------------------------------------------------------


def require_auth(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not auth_mgr.validate_session(token):
        raise HTTPException(status_code=401, detail="未登录或会话已过期，请重新登录")
    return True


# ---------------------------------------------------------------------------
# WebSocket：扫描日志/状态实时广播，取代前端原来每 1.2 秒一次的轮询。
# WS 握手阶段拿不到 Depends(require_auth) 这套 HTTP 中间件机制，
# 必须手动从 ws.cookies 里取 session token 校验，未登录直接拒绝并关闭。
# ---------------------------------------------------------------------------


@app.websocket("/ws/logs")
async def ws_logs(ws: WebSocket):
    token = ws.cookies.get(SESSION_COOKIE)
    if not auth_mgr.validate_session(token):
        await ws.close(code=4401)
        return

    await ws_manager.connect(ws)
    try:
        # 连接建立时先把当前已有的日志/运行状态整体推一遍，
        # 这样客户端不需要额外再发一次 HTTP 请求去"补齐历史"，WS 单通道就够。
        await ws.send_json({"type": "log_backfill", "entries": state.get_logs_since(0)})
        await ws.send_json({
            "type": "status",
            "running": state.running,
            "has_results": state.results is not None,
        })
        while True:
            # 不需要客户端真的发消息，这里只是用来感知"对端主动关闭"这个事件；
            # 浏览器标签页关闭 / 弱网断线时，这行会抛出 WebSocketDisconnect。
            await ws.receive_text()
    except WebSocketDisconnect:
        pass
    except Exception:
        logging.getLogger("ws_manager").exception("ws_logs 连接异常")
    finally:
        await ws_manager.disconnect(ws)


class LoginIn(BaseModel):
    password: str
    totp_code: str | None = None


@app.post("/api/login")
def login(body: LoginIn, request: Request, response: Response):
    ip = get_client_ip(request)
    locked_remain = auth_mgr.is_locked(ip)
    if locked_remain > 0:
        raise HTTPException(
            status_code=429,
            detail=f"登录尝试次数过多，账户已锁定，请在 {int(locked_remain) + 1} 秒后重试",
        )
    if not auth_mgr.verify_password(body.password):
        auth_mgr.register_failure(ip)
        remain = auth_mgr.is_locked(ip)
        _record_audit(request, "login_failed", f"ip={ip}")
        if remain > 0:
            raise HTTPException(
                status_code=429,
                detail=f"密码错误次数过多，已锁定 {int(remain)} 秒后再试",
            )
        raise HTTPException(status_code=401, detail="密码错误")

    if auth_mgr.is_totp_enabled():
        if not body.totp_code:
            # 密码正确但还没提供两步验证码：不算失败次数，前端据此弹出验证码输入框
            raise HTTPException(status_code=401, detail={"code": "totp_required", "message": "请输入两步验证码"})
        if not auth_mgr.verify_totp(body.totp_code):
            auth_mgr.register_failure(ip)
            remain = auth_mgr.is_locked(ip)
            _record_audit(request, "login_failed_totp", f"ip={ip}")
            if remain > 0:
                raise HTTPException(status_code=429, detail=f"验证码错误次数过多，已锁定 {int(remain)} 秒后再试")
            raise HTTPException(status_code=401, detail={"code": "totp_required", "message": "验证码错误"})

    auth_mgr.register_success(ip)
    token = auth_mgr.create_session()
    response.set_cookie(
        SESSION_COOKIE,
        token,
        httponly=True,
        samesite="strict",
        secure=COOKIE_SECURE,
        max_age=12 * 3600,
        path="/",
    )
    _record_audit(request, "login_success", f"ip={ip}")
    return {"status": "ok"}


@app.post("/api/logout")
def logout(request: Request, response: Response):
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        auth_mgr.destroy_session(token)
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"status": "ok"}


@app.get("/api/session")
def session_check(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    return {"authenticated": auth_mgr.validate_session(token)}


@app.get("/api/totp/status")
def totp_status(auth=Depends(require_auth)):
    return {"enabled": auth_mgr.is_totp_enabled()}


@app.post("/api/totp/setup")
def totp_setup(auth=Depends(require_auth)):
    """生成一个新的密钥(暂不启用)，返回 otpauth:// URI 供 Google Authenticator / 其它 TOTP App 手动添加。
    没有内置二维码生成库，只能提供文本 URI/密钥，用户需要在 App 里手动输入或用其它二维码工具自行转换。"""
    secret = auth_mgr.generate_totp_secret()
    otpauth_url = f"otpauth://totp/OllamaScanner?secret={secret}&issuer=OllamaScanner"
    return {"secret": secret, "otpauth_url": otpauth_url}


class TotpEnableIn(BaseModel):
    code: str


@app.post("/api/totp/enable")
def totp_enable(body: TotpEnableIn, request: Request, auth=Depends(require_auth)):
    if not auth_mgr.enable_totp(body.code):
        raise HTTPException(status_code=400, detail="验证码不正确，请重新扫描/输入密钥后重试")
    _record_audit(request, "totp_enabled", "")
    return {"status": "ok"}


class TotpDisableIn(BaseModel):
    password: str


@app.post("/api/totp/disable")
def totp_disable(body: TotpDisableIn, request: Request, auth=Depends(require_auth)):
    if not auth_mgr.verify_password(body.password):
        raise HTTPException(status_code=401, detail="密码不正确")
    auth_mgr.disable_totp()
    _record_audit(request, "totp_disabled", "")
    return {"status": "ok"}


@app.get("/")
def root(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not auth_mgr.validate_session(token):
        return RedirectResponse(url="/login.html")
    return FileResponse(str(Path(__file__).parent.parent / "static" / "index.html"))


# ---------------------------------------------------------------------------
# 主机管理
# ---------------------------------------------------------------------------


def load_hosts():
    """
    主机记录格式: {"url": str, "enabled": bool, "favorite": bool, "tags": [str], "group": str}
    自动兼容旧版本(纯字符串列表 / 无 tags 字段 / 无 group 字段)数据, 迁移为新格式。
    """
    raw = _load_json_file(HOSTS_FILE, [])
    migrated = False
    hosts = []
    for item in raw:
        if isinstance(item, str):
            hosts.append({"url": item, "enabled": True, "favorite": False, "tags": [], "group": ""})
            migrated = True
        else:
            if "tags" not in item or "group" not in item:
                migrated = True
            hosts.append({
                "url": item.get("url"),
                "enabled": item.get("enabled", True),
                "favorite": item.get("favorite", False),
                "tags": item.get("tags", []),
                "group": item.get("group", ""),
            })
    if migrated:
        save_hosts(hosts)
    return hosts


def save_hosts(hosts):
    ordered = sorted(hosts, key=lambda h: not h.get("favorite", False))
    _save_json_file(HOSTS_FILE, ordered)


class HostIn(BaseModel):
    url: str
    tags: list[str] = []
    group: str = ""
    force: bool = False  # 探活失败时，前端二次确认后带上此字段强制新增


class HostPatch(BaseModel):
    url: str
    enabled: bool | None = None
    favorite: bool | None = None
    tags: list[str] | None = None
    group: str | None = None


def normalize_url(url: str) -> str:
    url = url.strip().rstrip("/")
    if not url:
        raise HTTPException(status_code=400, detail="地址不能为空")
    if len(url) > 512:
        raise HTTPException(status_code=400, detail="地址过长")
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url
    return url


def find_host(hosts, url):
    for h in hosts:
        if h["url"] == url:
            return h
    return None


def _probe_host_reachable(url: str, timeout: float = 3.0) -> tuple[bool, str]:
    """新增主机前的轻量探活：请求 Ollama 的 /api/tags，判断地址填错还是真的连不通。"""
    try:
        resp = requests.get(f"{url}/api/tags", timeout=timeout)
        if resp.status_code == 200:
            return True, ""
        return False, f"HTTP {resp.status_code}"
    except requests.exceptions.RequestException as e:
        return False, str(e)[:200]


def _host_scan_status_map():
    results = _load_json_file(RESULTS_FILE, {})
    return results.get("host_status", {})


def _enrich_host_status(hosts):
    status_map = _host_scan_status_map()
    for h in hosts:
        h["last_scan_status"] = status_map.get(h["url"], "unknown")
    return hosts


@app.get("/api/hosts")
def get_hosts(auth=Depends(require_auth)):
    return _enrich_host_status(load_hosts())


@app.delete("/api/hosts/all")
def delete_all_hosts(request: Request, auth=Depends(require_auth)):
    """一键清空整个主机列表（正常的 + 失败区的全部删掉），需要前端弹窗二次确认，
    这里不再额外要求密码——跟删单条主机的破坏力是同一个量级，保持一致的确认强度。"""
    with _hosts_lock:
        hosts = load_hosts()
        removed_urls = [h["url"] for h in hosts]
        save_hosts([])
    for url in removed_urls:
        _purge_host_from_leaderboard(url)
        _purge_host_from_ping_status(url)
    _record_audit(request, "delete_all_hosts", f"{len(removed_urls)} 个")
    return {"removed": len(removed_urls), "hosts": []}


@app.delete("/api/hosts/failed")
def delete_failed_hosts(request: Request, auth=Depends(require_auth)):
    """一键删除"失败区"里的主机(最近一次扫描 unreachable 或 all_down 的)，防止误连/误加回来。"""
    status_map = _host_scan_status_map()
    with _hosts_lock:
        hosts = load_hosts()
        to_remove = [h for h in hosts if status_map.get(h["url"]) in ("unreachable", "all_down")]
        if not to_remove:
            return {"removed": 0, "hosts": _enrich_host_status(hosts)}
        removed_urls = {h["url"] for h in to_remove}
        hosts = [h for h in hosts if h["url"] not in removed_urls]
        save_hosts(hosts)
        remaining = load_hosts()
    for url in removed_urls:
        _purge_host_from_leaderboard(url)
        _purge_host_from_ping_status(url)
    _record_audit(request, "delete_failed_hosts", f"{len(removed_urls)} 个: {', '.join(list(removed_urls)[:20])}")
    return {"removed": len(removed_urls), "hosts": _enrich_host_status(remaining)}


class HostBulkToggleIn(BaseModel):
    enabled: bool
    scope: str = "all"  # "all" | "failed" | "normal"


@app.post("/api/hosts/bulk-toggle")
def bulk_toggle_hosts(body: HostBulkToggleIn, request: Request, auth=Depends(require_auth)):
    status_map = _host_scan_status_map()
    with _hosts_lock:
        hosts = load_hosts()
        changed = 0
        for h in hosts:
            failed = status_map.get(h["url"]) in ("unreachable", "all_down")
            if body.scope == "failed" and not failed:
                continue
            if body.scope == "normal" and failed:
                continue
            if h.get("enabled", True) != body.enabled:
                h["enabled"] = body.enabled
                changed += 1
        save_hosts(hosts)
        result = load_hosts()
    _record_audit(request, "bulk_toggle_hosts", f"scope={body.scope} enabled={body.enabled} 影响{changed}个")
    return {"changed": changed, "hosts": _enrich_host_status(result)}


@app.post("/api/hosts")
def add_host(host: HostIn, request: Request, auth=Depends(require_auth)):
    url = normalize_url(host.url)
    if not host.force:
        archived_at = _find_url_in_archives(url)
        if archived_at:
            raise HTTPException(
                status_code=422,
                detail={
                    "code": "already_archived",
                    "message": f"该地址在归档「{archived_at['label']}」({archived_at['created_at'][:10]}) 里出现过，"
                                f"确认要重新添加的话可以强制添加",
                },
            )
        ok, err = _probe_host_reachable(url)
        if not ok:
            raise HTTPException(
                status_code=422,
                detail={
                    "code": "unreachable",
                    "message": f"无法连接到该地址（{err}），确认地址无误的话可以强制添加",
                },
            )
    with _hosts_lock:
        hosts = load_hosts()
        if find_host(hosts, url):
            raise HTTPException(status_code=400, detail="该地址已存在")
        hosts.append({"url": url, "enabled": True, "favorite": False, "tags": host.tags or [], "group": (host.group or "").strip()[:50]})
        save_hosts(hosts)
        result = load_hosts()
    _record_audit(request, "add_host", url)
    return _enrich_host_status(result)


@app.patch("/api/hosts")
def patch_host(patch: HostPatch, request: Request, auth=Depends(require_auth)):
    url = normalize_url(patch.url)
    with _hosts_lock:
        hosts = load_hosts()
        h = find_host(hosts, url)
        if not h:
            raise HTTPException(status_code=404, detail="未找到该地址")
        if patch.enabled is not None:
            h["enabled"] = patch.enabled
        if patch.favorite is not None:
            h["favorite"] = patch.favorite
        if patch.tags is not None:
            h["tags"] = patch.tags
        if patch.group is not None:
            h["group"] = patch.group.strip()[:50]
        save_hosts(hosts)
        result = load_hosts()
    _record_audit(request, "patch_host", url)
    return _enrich_host_status(result)


@app.delete("/api/hosts")
def delete_host(host: HostIn, request: Request, auth=Depends(require_auth)):
    url = normalize_url(host.url)
    with _hosts_lock:
        hosts = load_hosts()
        h = find_host(hosts, url)
        if not h:
            raise HTTPException(status_code=404, detail="未找到该地址")
        hosts.remove(h)
        save_hosts(hosts)
        remaining = load_hosts()
    remaining = _enrich_host_status(remaining)
    # 主机被移除后，排行榜和 ping 连通性状态里属于它的旧记录不会再被更新，
    # 顺手清掉避免这些文件随时间无限堆积陈旧数据。
    _purge_host_from_leaderboard(url)
    _purge_host_from_ping_status(url)
    _record_audit(request, "delete_host", url)
    return remaining


# ---------------------------------------------------------------------------
# 归档：把当前工作区(主机+排行榜+扫描结果)整体存一份快照，然后清空当前工作区，
# 让扫描台可以重新开始而不用担心界面堆满旧记录；数据本身不会丢，加新主机时还会
# 拿这些归档里的地址去查重，防止同一台机器被反复添加。
# ---------------------------------------------------------------------------


def _load_archives():
    return _load_json_file(ARCHIVES_FILE, [])


def _find_url_in_archives(url):
    for arc in _load_archives():
        for h in arc.get("hosts", []):
            if h.get("url") == url:
                return {"id": arc["id"], "label": arc.get("label") or arc["id"], "created_at": arc["created_at"]}
    return None


def _archive_summary(arc):
    discovered = arc.get("results", {}).get("discovered", {})
    model_count = sum(len(v) for v in discovered.values())
    return {
        "id": arc["id"],
        "label": arc.get("label") or arc["id"],
        "created_at": arc["created_at"],
        "host_count": len(arc.get("hosts", [])),
        "model_count": model_count,
    }


class ArchiveCreateIn(BaseModel):
    label: str = ""


# create_archive() 生成的 id 固定是 now.strftime("%Y%m%d_%H%M%S")，
# 这里锁死同样的格式作为白名单：请求路径里的 archive_id 不符合这个形状，
# 直接 400 拒绝，不进入任何查找/读盘逻辑。
# 现有实现里 archive_id 只是拿去跟内存里的 JSON 记录做字符串相等比较，
# 从未被拼接进文件系统路径，所以本身不构成路径穿越——这条正则是纵深防御，
# 防止未来有人改成 DATA_DIR / f"{archive_id}.json" 这种写法时才追悔莫及。
ARCHIVE_ID_RE = re.compile(r"^\d{8}_\d{6}$")


async def _load_json_file_async(path: Path, default):
    """归档/历史这类可能较大且被频繁访问的文件用异步 I/O 读，
    避免单进程模型下阻塞 FastAPI 的主事件循环（会连带卡住 WS 广播和其他请求）。
    小文件（如 hosts.json）没有这个必要，维持同步读即可。"""
    if not path.exists():
        return default
    async with aiofiles.open(path, "r", encoding="utf-8") as f:
        raw = await f.read()
    return json.loads(raw) if raw.strip() else default


@app.get("/api/archives")
async def list_archives(auth=Depends(require_auth)):
    archives = await _load_json_file_async(ARCHIVES_FILE, [])
    return [_archive_summary(a) for a in sorted(archives, key=lambda a: a["created_at"], reverse=True)]


@app.get("/api/archives/{archive_id}")
async def get_archive(archive_id: str, auth=Depends(require_auth)):
    if not ARCHIVE_ID_RE.match(archive_id):
        raise HTTPException(status_code=400, detail="非法的归档 ID")
    archives = await _load_json_file_async(ARCHIVES_FILE, [])
    for arc in archives:
        if arc["id"] == archive_id:
            return arc
    raise HTTPException(status_code=404, detail="未找到该归档")


@app.post("/api/archives")
def create_archive(body: ArchiveCreateIn, request: Request, auth=Depends(require_auth)):
    with _archives_lock:
        archives = _load_archives()
        now = datetime.now()
        archive_id = now.strftime("%Y%m%d_%H%M%S")
        label = body.label.strip()[:100] or now.strftime("%Y年%m月%d日 扫描存档")
        with _hosts_lock, _leaderboard_lock, _results_lock:
            snapshot = {
                "id": archive_id,
                "label": label,
                "created_at": now.isoformat(timespec="seconds"),
                "hosts": load_hosts(),
                "leaderboard": _load_json_file(LEADERBOARD_FILE, []),
                "results": _load_json_file(RESULTS_FILE, {}),
            }
            archives.append(snapshot)
            _save_json_file(ARCHIVES_FILE, archives)
            # 清空当前工作区：新界面从空白开始扫描，旧数据完整保留在归档里
            save_hosts([])
            _save_json_file(LEADERBOARD_FILE, [])
            _save_json_file(RESULTS_FILE, {})
    _record_audit(request, "create_archive", f"{label} ({len(snapshot['hosts'])}台主机)")
    return _archive_summary(snapshot)


@app.delete("/api/archives/{archive_id}")
def delete_archive(archive_id: str, request: Request, auth=Depends(require_auth)):
    with _archives_lock:
        archives = _load_archives()
        before = len(archives)
        archives = [a for a in archives if a["id"] != archive_id]
        if len(archives) == before:
            raise HTTPException(status_code=404, detail="未找到该归档")
        _save_json_file(ARCHIVES_FILE, archives)
    _record_audit(request, "delete_archive", archive_id)
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# 模型汇总("模型恢复测试")：不管这个 主机+模型 是在当前工作区还是躺在某个归档里，
# 都汇总到一个界面，每条都带着主机地址；可以现场重新测一遍它是不是还在线、
# 是否支持无头浏览器 —— 用来"恢复"那些被归档、但机器可能其实还活着的记录。
# ---------------------------------------------------------------------------


def _build_all_models_registry():
    entries = {}
    # 先放归档的（按时间正序），最后放当前工作区的，同一个 主机+模型 后来的会覆盖先来的，
    # 这样如果同一个地址在当前工作区和某次归档里都出现过，显示的是"当前"而不是过时的归档标签。
    archives = sorted(_load_archives(), key=lambda a: a["created_at"])
    for arc in archives:
        discovered = arc.get("results", {}).get("discovered", {})
        viability = arc.get("results", {}).get("viability", {})
        for host, models in discovered.items():
            for m in models:
                key = f"{host}|{m}"
                entries[key] = {
                    "host": host, "model": m,
                    "family_hint": guess_model_family(m),
                    "source": "archive", "source_label": arc.get("label") or arc["id"], "source_id": arc["id"],
                    "last_known_ok": viability.get(key),
                }
    current = _load_json_file(RESULTS_FILE, {})
    for host, models in current.get("discovered", {}).items():
        for m in models:
            key = f"{host}|{m}"
            entries[key] = {
                "host": host, "model": m,
                "family_hint": guess_model_family(m),
                "source": "current", "source_label": "当前工作区", "source_id": None,
                "last_known_ok": current.get("viability", {}).get(key),
            }
    return list(entries.values())


@app.get("/api/models/all")
def list_all_models(auth=Depends(require_auth)):
    return _build_all_models_registry()


class ModelRefIn(BaseModel):
    host: str
    model: str


class ModelBatchIn(BaseModel):
    items: list[ModelRefIn] | None = None  # 不传则默认对汇总里的全部模型操作


def _resolve_batch_items(body: "ModelBatchIn"):
    if body.items:
        return [(i.host, i.model) for i in body.items]
    return [(e["host"], e["model"]) for e in _build_all_models_registry()]


@app.post("/api/models/quick-test-batch")
def models_quick_test_batch(body: ModelBatchIn, auth=Depends(require_auth)):
    """现场重新测一遍在线状态+响应速度，在线优先、按耗时升序返回 —— 给"模型汇总"界面的在线排行用。"""
    import concurrent.futures

    items = _resolve_batch_items(body)
    rows = []

    def _one(host, model):
        ok, err, elapsed = quick_test(host, model)
        return {"host": host, "model": model, "ok": ok, "elapsed": elapsed, "error": err if not ok else None}

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(_one, h, m) for h, m in items]
        for f in concurrent.futures.as_completed(futures):
            try:
                rows.append(f.result())
            except Exception as e:
                rows.append({"host": "?", "model": "?", "ok": False, "elapsed": None, "error": str(e)})

    rows.sort(key=lambda r: (r["ok"] is not True, r["elapsed"] if r["elapsed"] is not None else float("inf")))
    for i, r in enumerate(rows):
        r["rank"] = i + 1 if r["ok"] else None
    return rows


@app.post("/api/models/headless-test")
def model_headless_test(body: ModelRefIn, auth=Depends(require_auth)):
    """单个 主机+模型 现场跑一遍无头浏览器测试，返回是否支持 + 每道题的细节。"""
    tmp_state = ScanState()
    ok, details = run_headless_tests_only(body.host, body.model, tmp_state)
    return {"host": body.host, "model": body.model, "supported": ok, "details": details}


@app.post("/api/models/headless-test-batch")
def models_headless_test_batch(body: ModelBatchIn, auth=Depends(require_auth)):
    """一键给一批(默认"当前在线"的全部)模型跑无头浏览器测试，并发但限制并发数避免同时打爆很多台主机。"""
    import concurrent.futures

    items = _resolve_batch_items(body)
    tmp_state = ScanState()
    rows = []

    def _one(host, model):
        ok, details = run_headless_tests_only(host, model, tmp_state)
        return {"host": host, "model": model, "supported": ok, "details": details}

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        futures = [pool.submit(_one, h, m) for h, m in items]
        for f in concurrent.futures.as_completed(futures):
            try:
                rows.append(f.result())
            except Exception as e:
                rows.append({"host": "?", "model": "?", "supported": False, "details": [{"name": "-", "status": "ERROR", "detail": str(e)}]})
    return rows


# ---------------------------------------------------------------------------
# 地球可视化：给新版指挥中心风格界面用。核心思路是"能查到公网地理位置就画点，查不到就归到
# 内网/未知这一堆"——不依赖任何地图数据文件或前端地图库（部署环境不一定有), 用免费的
# ip-api.com 查公网IP的大致地理位置(国家/城市/经纬度)，查询结果本地缓存，避免重复调用。
# 只解析域名对应的IP用于查地理位置，不做真正的网络扫描/端口探测意义之外的事情。
# ---------------------------------------------------------------------------


def _extract_host_port(url: str):
    p = urlparse(url)
    return (p.hostname or ""), p.port


def _resolve_ip(hostname: str):
    try:
        return socket.gethostbyname(hostname)
    except Exception:
        return None


def _is_private_or_unroutable_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved or addr.is_multicast
    except Exception:
        return True  # 解析不出来就当内网/未知处理，不发起外部地理位置查询


def _geolocate_self():
    """内网/无法解析的主机查不到自己的地理位置，但它们大概率和本服务器共用同一个
    出口公网IP（同一个内网/同一个NAT出口），所以退而求其次：查一次"本机出口IP"
    的大概地理位置，给这些内网主机当兜底坐标用，好歹能在地球上显示出来，而不是
    干脆不显示。本地缓存7天（出口IP比服务器本身的IP更容易变，缓存时间比单个公网
    IP的缓存(31天)短一些）；查询失败也短暂负缓存，避免容器没有出网权限时每6秒
    轮询都重新发起一次注定失败的请求。"""
    with _geoip_lock:
        cache = _load_geoip_cache()
        cached = cache.get("__self__")
    if cached:
        try:
            age_minutes = (datetime.now() - datetime.fromisoformat(cached["cached_at"])).total_seconds() / 60
            if cached.get("failed"):
                if age_minutes < GEOIP_NEG_CACHE_MINUTES:
                    return None
            elif age_minutes < 7 * 24 * 60:
                return cached
        except Exception:
            pass

    try:
        resp = requests.get(
            "http://ip-api.com/json/?fields=status,country,countryCode,city,lat,lon,query", timeout=3
        )
        data = resp.json()
        if data.get("status") != "success":
            result = None
        else:
            result = {
                "country": data.get("country"),
                "country_code": data.get("countryCode"),
                "city": data.get("city"),
                "lat": data.get("lat"),
                "lon": data.get("lon"),
                "self_ip": data.get("query"),
                "cached_at": datetime.now().isoformat(timespec="seconds"),
            }
    except Exception:
        result = None

    cache_entry = result if result else {"failed": True, "cached_at": datetime.now().isoformat(timespec="seconds")}
    with _geoip_lock:
        cache = _load_geoip_cache()
        cache["__self__"] = cache_entry
        _save_json_file(GEOIP_CACHE_FILE, cache)
    return result


def _load_geoip_cache():
    return _load_json_file(GEOIP_CACHE_FILE, {})


GEOIP_NEG_CACHE_MINUTES = 15  # 查询失败的IP，15分钟内不再重试，避免被限流后陷入"每6秒轮询都重试全部失败IP"的死循环
GEOIP_MAX_NEW_LOOKUPS_PER_BUILD = 8  # 每次构建地球数据，最多现查这么多个"从没查过/缓存过期"的新IP，主机很多时分批查，不要一次性同步查几十个把接口拖死


_CF_CHALLENGE_MARKERS = (
    "just a moment", "cf-browser-verification", "challenge-platform",
    "checking your browser", "attention required! | cloudflare",
    "cdn-cgi/challenge-platform", "cf-challenge", "turnstile",
)

# 从网页正文里提取 ip:port，默认更偏向 11434（Ollama默认端口），但不限定端口，
# 因为用户可能用别的端口。跟批量粘贴用的是同一套思路。
_ADDR_RE = re.compile(r"(?:https?://)?(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?")


def _looks_like_cf_challenge(status_code: int, text: str) -> bool:
    if status_code in (403, 503):
        low = (text or "").lower()
        if any(marker in low for marker in _CF_CHALLENGE_MARKERS):
            return True
        if status_code == 503 and "cloudflare" in low:
            return True
    low = (text or "").lower()
    return any(marker in low for marker in _CF_CHALLENGE_MARKERS)


def _fetch_and_extract_addresses(url: str, default_port: str = "11434"):
    """访问一个网页(自己的域名/内网地址都行)，从返回内容里提取 ip[:port] 地址。
    返回 (status, message, found_urls)：
      status = "ok"          正常拿到内容并解析（找不到地址也算 ok，found_urls 可能是空列表）
      status = "cf_blocked"  响应看起来是 Cloudflare 的验证挑战页，不是真实内容
      status = "error"       请求本身失败（超时/DNS/连接被拒绝等）
    """
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }
    try:
        resp = requests.get(url, headers=headers, timeout=8)
    except Exception as e:
        return "error", f"请求失败：{type(e).__name__}: {e}", []

    text = resp.text or ""
    if _looks_like_cf_challenge(resp.status_code, text):
        return (
            "cf_blocked",
            f"拿到的内容像是 Cloudflare 的验证挑战页（HTTP {resp.status_code}），不是网页真实内容。"
            f"这不是代码能直接绕过的——Cloudflare 的JS挑战需要真的执行JS才能过，普通HTTP请求做不到。"
            f"建议：在 Cloudflare 后台给这个路径/本服务器出口IP加一条「跳过安全检查」的规则，"
            f"或者干脆把发布这个地址的页面放在一个不接入CF代理（DNS-only/灰色云朵）的子域名下。",
            [],
        )
    if resp.status_code >= 400:
        return "error", f"网页返回了 HTTP {resp.status_code}", []

    matches = []
    seen = set()
    for m in _ADDR_RE.finditer(text):
        ip, port = m.group(1), m.group(2) or default_port
        addr = f"http://{ip}:{port}"
        if addr not in seen:
            seen.add(addr)
            matches.append(addr)
    return "ok", f"成功获取网页内容，提取到 {len(matches)} 个地址" if matches else "成功获取网页内容，但没有提取到任何 ip:port 地址", matches


def _auto_add_discovered_host(url: str, group: str, tags: list):
    """后台自动发现流程专用的"加主机"，跟 POST /api/hosts 那个面向用户请求的接口不同：
    不做存活探测（内网地址可能刚变化，这一刻探测不通不代表地址是错的，交给下一次扫描去判断
    是否可用），已存在/已归档过的直接跳过，不抛异常（这里没有 HTTP 请求上下文可抛）。"""
    try:
        norm = normalize_url(url)
    except Exception:
        return False
    with _hosts_lock:
        hosts = load_hosts()
        if find_host(hosts, norm):
            return False
        hosts.append({"url": norm, "enabled": True, "favorite": False, "tags": tags or [], "group": (group or "").strip()[:50]})
        save_hosts(hosts)
    return True
    """只读缓存，不发网络请求。返回 (is_fresh, result)：
    is_fresh=True 且 result 有值 → 直接能用；
    is_fresh=True 且 result=None → 之前查过失败，还在负缓存有效期内，不用再查；
    is_fresh=False → 缓存里没有或者已经过期，需要重新发起网络请求。"""
    with _geoip_lock:
        cache = _load_geoip_cache()
        cached = cache.get(ip)
    if not cached:
        return False, None
    try:
        age_minutes = (datetime.now() - datetime.fromisoformat(cached["cached_at"])).total_seconds() / 60
        if cached.get("failed"):
            return (True, None) if age_minutes < GEOIP_NEG_CACHE_MINUTES else (False, None)
        return (True, cached) if age_minutes < 31 * 24 * 60 else (False, None)
    except Exception:
        return False, None


def _geoip_fetch_and_cache(ip: str):
    """真正发起一次网络查询并写入缓存（成功/失败都缓存）。调用方负责限流/并发控制，
    这里只管单个IP的查询逻辑。"""
    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,lat,lon", timeout=3
        )
        data = resp.json()
        if data.get("status") != "success":
            result = None
        else:
            result = {
                "country": data.get("country"),
                "country_code": data.get("countryCode"),
                "city": data.get("city"),
                "lat": data.get("lat"),
                "lon": data.get("lon"),
                "cached_at": datetime.now().isoformat(timespec="seconds"),
            }
    except Exception:
        result = None

    cache_entry = result if result else {"failed": True, "cached_at": datetime.now().isoformat(timespec="seconds")}
    with _geoip_lock:
        cache = _load_geoip_cache()
        cache[ip] = cache_entry
        _save_json_file(GEOIP_CACHE_FILE, cache)
    return result


def _build_globe_points():
    """给地球界面用：能直接查到公网地理位置的主机各自一个点；查不到的（内网IP/域名
    解析失败）会用本服务器出口IP的位置兜底，这样也能显示在地球上（location_is_estimated=True
    标记出来，前端应提示这是估算位置）；连兜底查询都失败（没有出网权限）的才会落到
    "未定位"分组，前端在角落用一个"内网 XX 条"的readout展示，而不是硬凑一个假坐标。

    主机很多时（几十上百台），"每个主机各查一次地理位置"如果同步做、又不限量，
    会导致这个接口被拖得很慢（httpx-log0前端每6秒轮询一次），还容易把ip-api.com
    免费版45次/分钟的限流打满。所以这里先把"这次请求里，哪些IP是从没查过/缓存
    已过期"挑出来，最多并发查 GEOIP_MAX_NEW_LOOKUPS_PER_BUILD 个；查不完的这一批
    留到下一次轮询（6秒后）继续查，直到全部进入缓存（之后就是纯读缓存，很快）。"""
    hosts = load_hosts()
    results = _load_json_file(RESULTS_FILE, {})
    discovered = results.get("discovered", {})
    viability = results.get("viability", {})

    resolved = []  # [(row_partial, ip_or_None, is_public)]
    for h in hosts:
        url = h["url"]
        hostname, port = _extract_host_port(url)
        try:
            ipaddress.ip_address(hostname)
            ip = hostname
        except ValueError:
            ip = _resolve_ip(hostname) if hostname else None

        models = discovered.get(url, [])
        ok_count = sum(1 for m in models if viability.get(f"{url}|{m}"))
        row = {
            "host": url,
            "domain_or_ip": hostname,
            "port": port,
            "model_count": len(models),
            "ok_count": ok_count,
            "group": h.get("group", ""),
            "tags": h.get("tags", []),
            "enabled": h.get("enabled", True),
        }
        is_public = bool(ip) and not _is_private_or_unroutable_ip(ip)
        resolved.append((row, ip if is_public else None, is_public))

    # 找出这次需要新发起查询的公网IP（缓存里没有或已过期），限量并发查询
    need_fetch = []
    seen = set()
    for _row, ip, is_public in resolved:
        if is_public and ip not in seen:
            seen.add(ip)
            is_fresh, _ = _geoip_cache_get(ip)
            if not is_fresh:
                need_fetch.append(ip)
    need_fetch = need_fetch[:GEOIP_MAX_NEW_LOOKUPS_PER_BUILD]
    if need_fetch:
        with ThreadPoolExecutor(max_workers=min(8, len(need_fetch))) as pool:
            list(pool.map(_geoip_fetch_and_cache, need_fetch))

    # 是否需要出口IP兜底定位：只要有至少一台内网/解析失败的主机就查一次（整批只查一次）
    self_geo_cache = {"value": None, "fetched": False}

    def get_self_geo():
        if not self_geo_cache["fetched"]:
            self_geo_cache["value"] = _geolocate_self()
            self_geo_cache["fetched"] = True
        return self_geo_cache["value"]

    points, unlocated = [], []
    for row, ip, is_public in resolved:
        geo = None
        geo_is_fallback = False
        if is_public:
            _, geo = _geoip_cache_get(ip)  # 这次批量查询后缓存应该已经是最新的了
        if geo is None:
            geo = get_self_geo()
            geo_is_fallback = True

        if geo:
            row.update({
                "located": True,
                "country": geo["country"],
                "country_code": geo.get("country_code"),
                "city": geo.get("city"),
                "lat": geo["lat"],
                "lon": geo["lon"],
                "location_is_estimated": geo_is_fallback,
            })
            points.append(row)
        else:
            row.update({"located": False, "country": None, "city": None, "lat": None, "lon": None})
            unlocated.append(row)

    return {"points": points, "unlocated": unlocated}


class CompanySettingsIn(BaseModel):
    name: str = ""
    address: str = ""
    lat: float | None = None
    lon: float | None = None


@app.get("/api/globe/company")
def get_company_location(auth=Depends(require_auth)):
    return _load_settings().get("company", DEFAULT_SETTINGS["company"])


@app.put("/api/globe/company")
def put_company_location(body: CompanySettingsIn, request: Request, auth=Depends(require_auth)):
    with _settings_lock:
        raw = _load_json_file(SETTINGS_FILE, {})
        settings = _deep_merge_defaults(DEFAULT_SETTINGS, raw)
        settings["company"] = body.model_dump()
        _save_json_file(SETTINGS_FILE, settings)
    _record_audit(request, "update_company_location", body.name or body.address or "(未命名)")
    return settings["company"]


@app.post("/api/globe/cache/clear")
def globe_cache_clear(auth=Depends(require_auth)):
    """诊断/急救用：清空地理位置缓存（包括之前查询失败被负缓存15分钟的条目），
    让下一次 /api/globe/points 对所有IP重新查一遍，不用等负缓存自然过期或者手动
    上容器删文件。"""
    had_file = GEOIP_CACHE_FILE.exists()
    try:
        if had_file:
            GEOIP_CACHE_FILE.unlink()
    except Exception as e:
        return {"cleared": False, "error": str(e)}
    return {"cleared": True, "had_file": had_file}


@app.get("/api/globe/debug")
def globe_debug(auth=Depends(require_auth)):
    """诊断用：直接测试一次"本服务器能不能查到IP地理位置"，绕开缓存。
    如果这里都查不到，说明是容器本身没有出网权限 / DNS解析不了 ip-api.com /
    出站流量被防火墙拦了，不是代码逻辑的问题，需要检查 Coolify/Docker 的网络配置。"""
    import traceback
    result = {"self_ip_test": None, "known_ip_test": None, "cache_file_exists": GEOIP_CACHE_FILE.exists()}

    try:
        resp = requests.get(
            "http://ip-api.com/json/?fields=status,message,country,countryCode,city,lat,lon,query", timeout=5
        )
        result["self_ip_test"] = {"http_status": resp.status_code, "body": resp.json()}
    except Exception as e:
        result["self_ip_test"] = {"error": f"{type(e).__name__}: {e}"}
        traceback.print_exc()

    try:
        resp = requests.get(
            "http://ip-api.com/json/8.8.8.8?fields=status,message,country,countryCode,city,lat,lon", timeout=5
        )
        result["known_ip_test"] = {"http_status": resp.status_code, "body": resp.json()}
    except Exception as e:
        result["known_ip_test"] = {"error": f"{type(e).__name__}: {e}"}
        traceback.print_exc()

    return result


@app.get("/api/globe/points")
def globe_points(auth=Depends(require_auth)):
    try:
        return _build_globe_points()
    except Exception as e:
        # 这里宁可返回一个"暂时没有数据"的空结构，也不要让整个接口 500——
        # 500 会导致前端这一轮轮询直接判定失败，"总览"/公司锚点该显示的数据也会跟着
        # 一起显示不出来。把异常打到日志里（docker logs 能看到），方便真定位问题。
        import traceback
        print(f"[globe_points] 构建地球数据时出错: {e}")
        traceback.print_exc()
        return {"points": [], "unlocated": [], "error": str(e)}


@app.get("/api/globe/country/{country}")
def globe_country_detail(country: str, auth=Depends(require_auth)):
    """点击地球上某个国家的光点：列出这个国家下面全部 主机+模型，供快速测试/无头浏览器测试用。"""
    data = _build_globe_points()
    hosts_in_country = [p for p in data["points"] if p["country"] == country]
    results = _load_json_file(RESULTS_FILE, {})
    discovered = results.get("discovered", {})
    viability = results.get("viability", {})
    models = []
    for p in hosts_in_country:
        for m in discovered.get(p["host"], []):
            key = f"{p['host']}|{m}"
            models.append({"host": p["host"], "model": m, "ok": viability.get(key), "city": p.get("city")})
    return {"country": country, "host_count": len(hosts_in_country), "models": models}


# ---------------------------------------------------------------------------
# 扫描控制
# ---------------------------------------------------------------------------


class ScanStartIn(BaseModel):
    concurrency: int = 3
    model_concurrency: int = 4
    enable_core: bool = True
    enable_control: bool = True
    enable_language: bool = True
    enable_headless: bool = False  # 无头浏览器测试是新增的重量级测试，默认不跑，需要显式开启


CATEGORY_LABELS = {
    "core": "核心测试",
    "control": "控制性 (Agent 工具调用)",
    "language": "语言性",
    "headless": "无头浏览器",
}

# 已知模型系列的模糊匹配表：仅用于给排行榜提供"这个标签名字看起来属于哪个厂商系列"
# 的粗略参考，不是任何实时联网比对结果，也不代表对具体版本号的质量评分——
# Ollama 里的模型标签可以被使用者随意自定义命名(比如加上 "claude"、"gpt" 等字样)，
# 无法从名字本身可靠验证它是否真的是对应厂商发布的模型，请自行核实来源。
KNOWN_MODEL_FAMILIES = [
    ("qwen", "阿里云 Qwen 系列"),
    ("deepseek", "DeepSeek 系列"),
    ("glm", "智谱 GLM 系列"),
    ("llama", "Meta Llama 系列"),
    ("gemma", "Google Gemma 系列"),
    ("gemini", "Google Gemini 系列"),
    ("mistral", "Mistral AI 系列"),
    ("mixtral", "Mistral AI 系列"),
    ("phi", "Microsoft Phi 系列"),
    ("gpt-oss", "OpenAI 开源 GPT-OSS 系列"),
    ("minimax", "MiniMax 系列"),
    ("kimi", "月之暗面 Kimi 系列"),
    ("moonshot", "月之暗面 Kimi 系列"),
    ("nemotron", "NVIDIA Nemotron 系列"),
    ("command-r", "Cohere Command-R 系列"),
    ("yi", "零一万物 Yi 系列"),
    ("internlm", "上海AI实验室 InternLM 系列"),
    ("starcoder", "BigCode StarCoder 系列"),
    ("codellama", "Meta Code Llama 系列"),
    ("claude", "标签含 claude 字样(⚠️ Anthropic 并未向 Ollama 生态发布过官方模型，请务必自行核实来源，不要默认信任)"),
]


def _purge_host_from_leaderboard(url):
    with _leaderboard_lock:
        lb = _load_json_file(LEADERBOARD_FILE, [])
        kept = [e for e in lb if e.get("host") != url]
        if len(kept) != len(lb):
            _save_json_file(LEADERBOARD_FILE, kept)


def _purge_host_from_ping_status(url):
    with _ping_lock:
        status = _load_json_file(PING_STATUS_FILE, {})
        prefix = f"{url}|"
        kept = {k: v for k, v in status.items() if not k.startswith(prefix)}
        if len(kept) != len(status):
            _save_json_file(PING_STATUS_FILE, kept)


def _record_audit(request: Request, action: str, detail: str = ""):
    """记录一条操作审计日志：谁（来源IP）在什么时候做了什么。
    单管理员场景下没有用户名概念，用来源 IP 作为操作者标识。"""
    entry = {
        "ts": datetime.now().isoformat(timespec="seconds"),
        "ip": get_client_ip(request),
        "action": action,
        "detail": detail,
    }
    with _audit_lock:
        logs = _load_json_file(AUDIT_LOG_FILE, [])
        logs.append(entry)
        if len(logs) > AUDIT_LOG_MAX_ENTRIES:
            logs = logs[-AUDIT_LOG_MAX_ENTRIES:]
        _save_json_file(AUDIT_LOG_FILE, logs)


class LanguageRuleIn(BaseModel):
    type: str
    n: int | None = None
    word: str | None = None
    count: int | None = None
    words: list[str] | None = None


class CustomLanguageTestIn(BaseModel):
    name: str
    prompt: str
    rules: list[LanguageRuleIn] = []


@app.get("/api/custom-tests")
def list_custom_tests(auth=Depends(require_auth)):
    return _load_settings().get("custom_language_tests", [])


@app.post("/api/custom-tests")
def create_custom_test(body: CustomLanguageTestIn, request: Request, auth=Depends(require_auth)):
    if not body.prompt.strip():
        raise HTTPException(status_code=400, detail="prompt 不能为空")
    with _settings_lock:
        raw = _load_json_file(SETTINGS_FILE, {})
        settings = _deep_merge_defaults(DEFAULT_SETTINGS, raw)
        entry = {
            "id": secrets.token_hex(6),
            "name": body.name.strip()[:100] or "未命名用例",
            "prompt": body.prompt.strip(),
            "rules": [r.model_dump() for r in body.rules],
        }
        settings["custom_language_tests"].append(entry)
        _save_json_file(SETTINGS_FILE, settings)
    _record_audit(request, "custom_test_create", entry["name"])
    return entry


@app.delete("/api/custom-tests/{test_id}")
def delete_custom_test(test_id: str, request: Request, auth=Depends(require_auth)):
    with _settings_lock:
        raw = _load_json_file(SETTINGS_FILE, {})
        settings = _deep_merge_defaults(DEFAULT_SETTINGS, raw)
        before = len(settings["custom_language_tests"])
        settings["custom_language_tests"] = [t for t in settings["custom_language_tests"] if t.get("id") != test_id]
        changed = len(settings["custom_language_tests"]) != before
        if changed:
            _save_json_file(SETTINGS_FILE, settings)
    if not changed:
        raise HTTPException(status_code=404, detail="未找到该测试用例")
    _record_audit(request, "custom_test_delete", test_id)
    return {"status": "ok"}


class CustomCoreTestIn(BaseModel):
    password: str        # 二次确认：因为这会在服务器沙箱子进程里真实执行任意代码
    name: str
    prompt: str
    harness: str
    expected: str = "ALL_PASS"


@app.get("/api/custom-tests/core")
def list_custom_core_tests(auth=Depends(require_auth)):
    # 不返回 harness 源码到列表接口，避免在前端到处明文出现；需要看内容可以在创建时留存的名字里体现
    return [{"id": t["id"], "name": t["name"], "prompt": t["prompt"]} for t in _load_settings().get("custom_core_tests", [])]


@app.post("/api/custom-tests/core")
def create_custom_core_test(body: CustomCoreTestIn, request: Request, auth=Depends(require_auth)):
    if not auth_mgr.verify_password(body.password):
        _record_audit(request, "custom_core_test_create_denied", "密码校验失败")
        raise HTTPException(status_code=401, detail="密码不正确")
    if not body.prompt.strip() or not body.harness.strip():
        raise HTTPException(status_code=400, detail="prompt 和 harness 不能为空")
    with _settings_lock:
        raw = _load_json_file(SETTINGS_FILE, {})
        settings = _deep_merge_defaults(DEFAULT_SETTINGS, raw)
        entry = {
            "id": secrets.token_hex(6),
            "name": body.name.strip()[:100] or "未命名用例",
            "prompt": body.prompt.strip(),
            "harness": body.harness,
            "expected": body.expected or "ALL_PASS",
        }
        settings["custom_core_tests"].append(entry)
        _save_json_file(SETTINGS_FILE, settings)
    # 强提醒：这条审计日志明确标注"会执行任意代码"，方便事后审查是谁在什么时候加了什么用例
    _record_audit(
        request,
        "custom_core_test_create",
        f"⚠️ 新增会在服务器沙箱执行任意代码的自定义核心测试用例：{entry['name']}",
    )
    return {"id": entry["id"], "name": entry["name"], "prompt": entry["prompt"]}


@app.delete("/api/custom-tests/core/{test_id}")
def delete_custom_core_test(test_id: str, request: Request, auth=Depends(require_auth)):
    with _settings_lock:
        raw = _load_json_file(SETTINGS_FILE, {})
        settings = _deep_merge_defaults(DEFAULT_SETTINGS, raw)
        before = len(settings["custom_core_tests"])
        settings["custom_core_tests"] = [t for t in settings["custom_core_tests"] if t.get("id") != test_id]
        changed = len(settings["custom_core_tests"]) != before
        if changed:
            _save_json_file(SETTINGS_FILE, settings)
    if not changed:
        raise HTTPException(status_code=404, detail="未找到该测试用例")
    _record_audit(request, "custom_core_test_delete", test_id)
    return {"status": "ok"}


@app.get("/api/audit-log")
def get_audit_log(auth=Depends(require_auth)):
    logs = _load_json_file(AUDIT_LOG_FILE, [])
    return list(reversed(logs))  # 最新的排前面


@app.get("/api/audit-log/export")
def export_audit_log(auth=Depends(require_auth)):
    import csv
    import io

    logs = list(reversed(_load_json_file(AUDIT_LOG_FILE, [])))
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["时间", "来源IP", "操作", "详情"])
    for entry in logs:
        writer.writerow([entry.get("ts", ""), entry.get("ip", ""), entry.get("action", ""), entry.get("detail", "")])
    content = "\ufeff" + buf.getvalue()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return Response(
        content=content,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="audit_log_{ts}.csv"'},
    )


# ---------------------------------------------------------------------------
# 设置：定时扫描 + 异常通知渠道
# ---------------------------------------------------------------------------


def _deep_merge_defaults(defaults, loaded):
    """把已保存的设置和默认结构做深度合并，保证以后新增字段时旧的 settings.json 不会缺键报错。"""
    if not isinstance(loaded, dict):
        return json.loads(json.dumps(defaults))
    merged = {}
    for k, dv in defaults.items():
        lv = loaded.get(k, None)
        if isinstance(dv, dict):
            merged[k] = _deep_merge_defaults(dv, lv if isinstance(lv, dict) else {})
        else:
            merged[k] = lv if lv is not None else dv
    return merged


def _load_settings():
    with _settings_lock:
        raw = _load_json_file(SETTINGS_FILE, {})
        return _deep_merge_defaults(DEFAULT_SETTINGS, raw)


def _save_settings(settings):
    with _settings_lock:
        _save_json_file(SETTINGS_FILE, settings)


@app.get("/api/settings")
def get_settings(auth=Depends(require_auth)):
    return _load_settings()


class NotifyWecomIn(BaseModel):
    enabled: bool = False
    webhook_url: str = ""


class NotifyTelegramIn(BaseModel):
    enabled: bool = False
    bot_token: str = ""
    chat_id: str = ""


class NotifyBarkIn(BaseModel):
    enabled: bool = False
    key: str = ""
    server: str = "https://api.day.app"


class NotifyEmailIn(BaseModel):
    enabled: bool = False
    smtp_host: str = ""
    smtp_port: int = 587
    username: str = ""
    password: str = ""
    from_addr: str = ""
    to_addr: str = ""
    use_tls: bool = True


class NotifySettingsIn(BaseModel):
    wecom: NotifyWecomIn = NotifyWecomIn()
    telegram: NotifyTelegramIn = NotifyTelegramIn()
    bark: NotifyBarkIn = NotifyBarkIn()
    email: NotifyEmailIn = NotifyEmailIn()


class ScheduleSettingsIn(BaseModel):
    enabled: bool = False
    time: str = "09:00"
    concurrency: int = 3
    model_concurrency: int = 4
    enable_core: bool = True
    enable_control: bool = True
    enable_language: bool = True
    enable_headless: bool = False


class HistorySettingsIn(BaseModel):
    retention_days: int = 180
    max_size_mb: int = 50
    auto_cleanup_enabled: bool = True


class SettingsIn(BaseModel):
    schedule: ScheduleSettingsIn = ScheduleSettingsIn()
    notify: NotifySettingsIn = NotifySettingsIn()
    history: HistorySettingsIn = HistorySettingsIn()


@app.put("/api/settings")
def put_settings(body: SettingsIn, request: Request, auth=Depends(require_auth)):
    import re
    if not re.match(r"^([01]\d|2[0-3]):[0-5]\d$", body.schedule.time or ""):
        raise HTTPException(status_code=400, detail="定时时间格式应为 HH:MM，例如 09:00")
    if body.history.retention_days <= 0:
        raise HTTPException(status_code=400, detail="retention_days 必须是正整数")
    if body.history.max_size_mb <= 0:
        raise HTTPException(status_code=400, detail="max_size_mb 必须是正整数")
    settings = body.model_dump()
    # "share"(分享链接)和 "metrics"(Prometheus 抓取)都不是这个表单管理的字段，
    # 通过各自独立的接口维护，这里如果整体覆盖写回会把已生成的 token 冲掉，所以从旧设置里保留下来。
    existing = _load_settings()
    settings["share"] = existing.get("share", DEFAULT_SETTINGS["share"])
    settings["metrics"] = existing.get("metrics", DEFAULT_SETTINGS["metrics"])
    settings["custom_language_tests"] = existing.get("custom_language_tests", DEFAULT_SETTINGS["custom_language_tests"])
    settings["custom_core_tests"] = existing.get("custom_core_tests", DEFAULT_SETTINGS["custom_core_tests"])
    settings["company"] = existing.get("company", DEFAULT_SETTINGS["company"])
    settings["address_discovery"] = existing.get("address_discovery", DEFAULT_SETTINGS["address_discovery"])
    _save_settings(settings)
    _record_audit(request, "update_settings", "已更新定时扫描/通知/历史数据设置")
    return settings


@app.post("/api/notify/test")
def notify_test(request: Request, auth=Depends(require_auth)):
    settings = _load_settings()
    enabled_channels = [k for k, v in settings.get("notify", {}).items() if v.get("enabled")]
    if not enabled_channels:
        raise HTTPException(status_code=400, detail="还没有启用任何通知渠道，先勾选并保存设置")
    _send_notifications("✅ Ollama 扫描台测试通知", "如果收到这条消息，说明该通知渠道配置正确。")
    _record_audit(request, "notify_test", f"渠道: {', '.join(enabled_channels)}")
    return {"status": "sent", "channels": enabled_channels}


# ---------------------------------------------------------------------------
# 地址自动发现：定期访问一个网页(自己的域名/内网地址都行)，从内容里提取 ip:port
# 自动加进主机列表——适合"内网地址会变、通过网站中转上报当前地址"这种场景。
# ---------------------------------------------------------------------------


class AddressDiscoveryIn(BaseModel):
    enabled: bool = False
    url: str = ""
    interval_minutes: int = 30
    group: str = ""
    tags: list[str] = []


@app.get("/api/settings/address-discovery")
def get_address_discovery(auth=Depends(require_auth)):
    return _load_settings().get("address_discovery", DEFAULT_SETTINGS["address_discovery"])


@app.put("/api/settings/address-discovery")
def put_address_discovery(body: AddressDiscoveryIn, request: Request, auth=Depends(require_auth)):
    if body.enabled and not body.url.strip():
        raise HTTPException(status_code=400, detail="开启自动发现需要先填目标网址")
    if body.interval_minutes < 5:
        raise HTTPException(status_code=400, detail="间隔不能小于5分钟，太频繁容易把对方网站/CDN 当成攻击流量")
    with _settings_lock:
        raw = _load_json_file(SETTINGS_FILE, {})
        settings = _deep_merge_defaults(DEFAULT_SETTINGS, raw)
        existing_ad = settings.get("address_discovery", DEFAULT_SETTINGS["address_discovery"])
        settings["address_discovery"] = {
            **existing_ad,
            "enabled": body.enabled,
            "url": body.url.strip(),
            "interval_minutes": body.interval_minutes,
            "group": body.group.strip()[:50],
            "tags": body.tags,
        }
        _save_json_file(SETTINGS_FILE, settings)
    _record_audit(request, "update_address_discovery", body.url or "(未设置)")
    return settings["address_discovery"]


@app.post("/api/settings/address-discovery/test")
def test_address_discovery(request: Request, auth=Depends(require_auth)):
    """立即测试一次，不等定时任务、不自动加主机，只是让你马上看到到底能不能拿到内容、
    拿到的是不是 Cloudflare 的验证页——方便你确认要不要去 Cloudflare 后台加白名单规则。"""
    settings = _load_settings()
    url = settings.get("address_discovery", {}).get("url", "").strip()
    if not url:
        raise HTTPException(status_code=400, detail="还没有配置目标网址")
    status, message, found = _fetch_and_extract_addresses(url)
    _record_audit(request, "test_address_discovery", f"{url} -> {status}")
    return {"status": status, "message": message, "found": found}


# ---------------------------------------------------------------------------
# 异常通知：发现主机/模型从「正常」变为「不可用」时，推送到配置好的渠道
# ---------------------------------------------------------------------------


def _notify_wecom(cfg, title, message):
    if not cfg.get("webhook_url"):
        return
    requests.post(cfg["webhook_url"], json={"msgtype": "text", "text": {"content": f"{title}\n{message}"}}, timeout=8)


def _notify_telegram(cfg, title, message):
    if not cfg.get("bot_token") or not cfg.get("chat_id"):
        return
    url = f"https://api.telegram.org/bot{cfg['bot_token']}/sendMessage"
    requests.post(url, json={"chat_id": cfg["chat_id"], "text": f"{title}\n{message}"}, timeout=8)


def _notify_bark(cfg, title, message):
    if not cfg.get("key"):
        return
    server = (cfg.get("server") or "https://api.day.app").rstrip("/")
    url = f"{server}/{cfg['key']}"
    requests.post(url, json={"title": title, "body": message, "group": "ollama-scanner"}, timeout=8)


def _notify_email(cfg, title, message):
    if not cfg.get("smtp_host") or not cfg.get("to_addr"):
        return
    import smtplib
    from email.mime.text import MIMEText

    msg = MIMEText(message, "plain", "utf-8")
    msg["Subject"] = title
    msg["From"] = cfg.get("from_addr") or cfg.get("username") or ""
    msg["To"] = cfg["to_addr"]

    with smtplib.SMTP(cfg["smtp_host"], int(cfg.get("smtp_port", 587)), timeout=10) as smtp:
        if cfg.get("use_tls", True):
            smtp.starttls()
        if cfg.get("username"):
            smtp.login(cfg["username"], cfg.get("password", ""))
        smtp.sendmail(msg["From"], [cfg["to_addr"]], msg.as_string())


_NOTIFY_SENDERS = {
    "wecom": _notify_wecom,
    "telegram": _notify_telegram,
    "bark": _notify_bark,
    "email": _notify_email,
}


def _send_notifications(title, message):
    settings = _load_settings()
    notify = settings.get("notify", {})
    for channel, sender in _NOTIFY_SENDERS.items():
        cfg = notify.get(channel, {})
        if not cfg.get("enabled"):
            continue
        try:
            sender(cfg, title, message)
        except Exception as e:
            # 单个渠道发送失败不应该影响其它渠道，记一笔审计方便排查（无 request 上下文，直接写日志文件）
            with _audit_lock:
                logs = _load_json_file(AUDIT_LOG_FILE, [])
                logs.append({
                    "ts": datetime.now().isoformat(timespec="seconds"),
                    "ip": "system",
                    "action": "notify_failed",
                    "detail": f"{channel}: {str(e)[:200]}",
                })
                if len(logs) > AUDIT_LOG_MAX_ENTRIES:
                    logs = logs[-AUDIT_LOG_MAX_ENTRIES:]
                _save_json_file(AUDIT_LOG_FILE, logs)


def _detect_regressions(prev_results, new_results):
    """对比本次和上一次扫描结果，找出「之前正常、这次变差」的主机/模型。返回通知正文，没有异常则返回 None。"""
    prev_viability = (prev_results or {}).get("viability", {}) or {}
    new_viability = (new_results or {}).get("viability", {}) or {}
    prev_hosts = set((prev_results or {}).get("discovered", {}).keys())
    new_hosts = set((new_results or {}).get("discovered", {}).keys())

    newly_unreachable_hosts = sorted(prev_hosts - new_hosts)
    newly_failed_models = sorted(
        key for key, ok in prev_viability.items()
        if ok and new_viability.get(key) is False
    )

    if not newly_unreachable_hosts and not newly_failed_models:
        return None

    lines = []
    if newly_unreachable_hosts:
        lines.append(f"主机完全不可达（{len(newly_unreachable_hosts)} 个）：")
        lines.extend(f"  · {h}" for h in newly_unreachable_hosts[:20])
    if newly_failed_models:
        lines.append(f"模型由正常变为不可用（{len(newly_failed_models)} 个）：")
        for key in newly_failed_models[:20]:
            host, model = key.split("|", 1)
            lines.append(f"  · {host} @ {model}")
    return "\n".join(lines)


def _launch_scan_and_watch(hosts, concurrency, model_concurrency, enable_core=True, enable_control=True, enable_language=True, enable_headless=False):
    """启动一次扫描，并在后台等它跑完后做异常对比 + 发通知。手动触发和定时触发共用这个入口。"""
    prev_results = _load_json_file(RESULTS_FILE, {})
    refresh_custom_language_cases(_load_settings().get("custom_language_tests", []))
    refresh_custom_core_cases(_load_settings().get("custom_core_tests", []))
    set_test_categories_enabled(core=enable_core, control=enable_control, language=enable_language, headless=enable_headless)
    ok = start_scan_thread(hosts, state, concurrency=concurrency, model_concurrency=model_concurrency)
    if not ok:
        return False

    def _watch():
        while state.running:
            time.sleep(2)
        new_results = state.results
        if new_results is None:
            return
        msg = _detect_regressions(prev_results, new_results)
        if msg:
            _send_notifications("⚠️ Ollama 集群扫描发现新异常", msg)

    threading.Thread(target=_watch, daemon=True).start()
    return True


# ---------------------------------------------------------------------------
# 定时扫描：每天固定时间自动跑一次全量扫描（时间可在设置里改，无需重启容器）
# ---------------------------------------------------------------------------

_last_scheduled_run_date = None
_last_history_snapshot_generated_at = None


def _scheduler_loop():
    global _last_scheduled_run_date
    _cycles = 0
    while True:
        time.sleep(20)
        _cycles += 1
        if _cycles % 180 == 0:  # 大约每 1 小时清理一次历史数据，不依赖是否刚好有扫描完成
            try:
                _enforce_history_limits()
            except Exception:
                pass
        # 地址自动发现：跟下面的定时扫描是两件独立的事，各自 try/except，互不连累。
        # 注意：必须放在定时扫描那段逻辑之前——那段逻辑里有好几个 continue，一旦触发
        # 会跳过本次循环剩下的全部代码，如果放在它后面，只要没开每日定时扫描
        # （最常见的情况），这里就永远不会被执行到。
        try:
            settings = _load_settings()
            ad = settings.get("address_discovery", {})
            url = (ad.get("url") or "").strip()
            if ad.get("enabled") and url:
                interval = max(5, int(ad.get("interval_minutes", 30)))
                last_run_at = ad.get("last_run_at")
                due = True
                if last_run_at:
                    try:
                        elapsed = (datetime.now() - datetime.fromisoformat(last_run_at)).total_seconds() / 60
                        due = elapsed >= interval
                    except Exception:
                        due = True
                if due:
                    status, message, found = _fetch_and_extract_addresses(url)
                    added = 0
                    if status == "ok" and found:
                        for addr in found:
                            if _auto_add_discovered_host(addr, ad.get("group", ""), ad.get("tags", [])):
                                added += 1
                    if added:
                        message += f"，新增了 {added} 个主机"
                        state.log(f"[地址自动发现] 从 {url} 提取到 {len(found)} 个地址，新增了 {added} 个")
                    with _settings_lock:
                        raw = _load_json_file(SETTINGS_FILE, {})
                        settings2 = _deep_merge_defaults(DEFAULT_SETTINGS, raw)
                        settings2["address_discovery"] = {
                            **settings2.get("address_discovery", DEFAULT_SETTINGS["address_discovery"]),
                            "last_run_at": datetime.now().isoformat(timespec="seconds"),
                            "last_status": status,
                            "last_message": message,
                            "last_found": found,
                        }
                        _save_json_file(SETTINGS_FILE, settings2)
        except Exception:
            pass

        try:
            settings = _load_settings()
            sched = settings.get("schedule", {})
            if not sched.get("enabled"):
                continue
            now = datetime.now()
            today = now.strftime("%Y-%m-%d")
            if now.strftime("%H:%M") != sched.get("time", "09:00"):
                continue
            if _last_scheduled_run_date == today:
                continue  # 这一天已经跑过了，避免同一分钟内被反复触发
            if state.running:
                continue  # 有正在进行的扫描（可能是手动触发的），跳过这次，等下一天
            hosts = [h["url"] for h in load_hosts() if h.get("enabled", True)]
            if not hosts:
                continue
            _last_scheduled_run_date = today
            _launch_scan_and_watch(
                hosts,
                max(1, min(100, sched.get("concurrency", 3))),
                max(1, min(20, sched.get("model_concurrency", 4))),
                enable_core=sched.get("enable_core", True),
                enable_control=sched.get("enable_control", True),
                enable_language=sched.get("enable_language", True),
                enable_headless=sched.get("enable_headless", False),
            )
        except Exception:
            pass  # 调度循环本身绝不能因为单次异常而退出


@app.on_event("startup")
def _start_background_threads():
    threading.Thread(target=_scheduler_loop, daemon=True).start()


def guess_model_family(model_name):
    """模糊匹配模型标签属于哪个已知厂商系列，仅供参考，不代表验证过真实性"""
    name_lower = (model_name or "").lower()
    for keyword, label in KNOWN_MODEL_FAMILIES:
        if keyword in name_lower:
            return label
    return None


def update_leaderboard_from_results(results):
    """扫描/重测得到的结果并入排行榜持久化文件。
    每个 主机+模型 按 core/control/language 三个类别分别统计：
    某一类全部通过才参与该类排名(按该类总耗时升序)；有失败项的只额外记录，不参与排名。"""
    if not results:
        return
    with _leaderboard_lock:
        lb = _load_json_file(LEADERBOARD_FILE, [])
        lb_map = {f"{e['host']}|{e['model']}": e for e in lb}
        for key, tests in results.get("advanced", {}).items():
            host, model = key.split("|", 1)
            _merge_leaderboard_entry(lb_map, host, model, tests)
        _save_json_file(LEADERBOARD_FILE, list(lb_map.values()))


def _merge_leaderboard_entry(lb_map, host, model, tests):
    key = f"{host}|{model}"
    entry = lb_map.get(key, {})
    existing_tests = entry.get("tests", [])
    incoming_categories = {t.get("category", "core") for t in tests}
    # 只替换这次实际测过的分类，没测到的分类(比如这次扫描关掉了"控制性测试"开关)保留旧记录，
    # 不然一开关某个测试类型，之前测出来的成绩就被整个冲掉了。
    kept_tests = [t for t in existing_tests if t.get("category", "core") not in incoming_categories]
    merged_tests = kept_tests + tests

    categories = {}
    for cat in CATEGORY_LABELS:
        cat_tests = [t for t in merged_tests if t.get("category", "core") == cat]
        total = len(cat_tests)
        if total == 0:
            continue
        passed = sum(1 for t in cat_tests if t.get("status") == "PASS")
        elapsed_total = round(sum(t.get("elapsed") or 0 for t in cat_tests), 2)
        categories[cat] = {
            "status": "pass" if passed == total else "fail",
            "passed": passed,
            "total": total,
            "elapsed_total": elapsed_total,
            "elapsed_avg": round(elapsed_total / total, 2) if total else None,
        }
    entry.update({
        "host": host,
        "model": model,
        "last_tested": datetime.now().isoformat(),
        "tests": merged_tests,
        "categories": categories,
    })
    lb_map[key] = entry
    return entry


@app.post("/api/scan/start")
def scan_start(body: ScanStartIn = ScanStartIn(), auth=Depends(require_auth)):
    hosts = [h["url"] for h in load_hosts() if h.get("enabled", True)]
    if not hosts:
        raise HTTPException(status_code=400, detail="请先添加并启用至少一个主机地址")
    if state.running:
        raise HTTPException(status_code=409, detail="扫描已在进行中")
    concurrency = max(1, min(100, body.concurrency))
    model_concurrency = max(1, min(20, body.model_concurrency))
    ok = _launch_scan_and_watch(
        hosts, concurrency, model_concurrency,
        enable_core=body.enable_core, enable_control=body.enable_control,
        enable_language=body.enable_language, enable_headless=body.enable_headless,
    )
    if not ok:
        raise HTTPException(status_code=409, detail="扫描已在进行中")
    return {"status": "started", "hosts": hosts, "concurrency": concurrency, "model_concurrency": model_concurrency}


@app.post("/api/scan/stop")
def scan_stop(auth=Depends(require_auth)):
    if not state.running:
        return {"status": "not_running"}
    state.request_stop()
    return {"status": "stopping"}


@app.get("/api/scan/status")
def scan_status(since: int = 0, auth=Depends(require_auth)):
    logs = state.get_logs_since(since)
    results = state.results
    global _last_history_snapshot_generated_at
    if results is not None:
        with _results_lock:
            _save_json_file(RESULTS_FILE, results)
        update_leaderboard_from_results(results)
        generated_at = results.get("generated_at")
        if generated_at and generated_at != _last_history_snapshot_generated_at:
            _append_history_snapshot(_build_leaderboard_view())
            _last_history_snapshot_generated_at = generated_at
            for key, ok in (results.get("viability") or {}).items():
                if "|" in key:
                    h, m = key.split("|", 1)
                    _record_uptime_sample(h, m, ok)
    return JSONResponse({
        "running": state.running,
        "logs": logs,
        "results": results,
    })


@app.get("/api/scan/results")
def scan_results(auth=Depends(require_auth)):
    return JSONResponse(_load_json_file(RESULTS_FILE, {}))


# ---------------------------------------------------------------------------
# 排行榜：按响应耗时排名，可对单个 主机+模型 一键重新测试
# ---------------------------------------------------------------------------


def _build_leaderboard_view():
    lb = _load_json_file(LEADERBOARD_FILE, [])
    result = {}
    for cat, label in CATEGORY_LABELS.items():
        ranked = []
        failed = []
        for e in lb:
            cat_data = (e.get("categories") or {}).get(cat)
            if not cat_data:
                continue
            row = {
                "host": e["host"],
                "model": e["model"],
                "family_hint": guess_model_family(e["model"]),
                "status": cat_data["status"],
                "passed": cat_data["passed"],
                "total": cat_data["total"],
                "elapsed_total": cat_data["elapsed_total"],
                "elapsed_avg": cat_data["elapsed_avg"],
                "last_tested": e.get("last_tested"),
                "error": e.get("error"),
            }
            if cat_data["status"] == "pass":
                ranked.append(row)
            else:
                failed.append(row)
        ranked.sort(key=lambda r: r["elapsed_total"] if r["elapsed_total"] is not None else float("inf"))
        for i, r in enumerate(ranked):
            r["rank"] = i + 1
        result[cat] = {"label": label, "ranked": ranked, "failed": failed}
    return result


@app.get("/api/leaderboard")
def get_leaderboard(auth=Depends(require_auth)):
    return _build_leaderboard_view()


def _build_quick_leaderboard_view():
    """"快速测试"视图：不评判回答质量，只看"这个模型现在能不能正常聊天、多快回应"。
    直接用最新一次扫描的可用性(viability)+响应耗时，在线的排前面(按耗时升序)，离线的放到 failed 里。"""
    results = _load_json_file(RESULTS_FILE, {})
    discovered = results.get("discovered", {})
    viability = results.get("viability", {})
    timing = results.get("viability_timing", {})
    generated_at = results.get("generated_at")

    ranked, failed = [], []
    for host, models in discovered.items():
        for m in models:
            key = f"{host}|{m}"
            ok = viability.get(key)
            row = {
                "host": host,
                "model": m,
                "family_hint": guess_model_family(m),
                "ok": ok,
                "elapsed": timing.get(key),
                "last_tested": generated_at,
            }
            (ranked if ok else failed).append(row)

    ranked.sort(key=lambda r: r["elapsed"] if r["elapsed"] is not None else float("inf"))
    for i, r in enumerate(ranked):
        r["rank"] = i + 1
    return {
        "label": "快速测试（模型可用性：真实调用一次模型验证，不是只测主机是否在线）",
        "ranked": ranked, "failed": failed, "generated_at": generated_at,
    }


@app.get("/api/leaderboard/quick")
def get_quick_leaderboard(auth=Depends(require_auth)):
    return _build_quick_leaderboard_view()


@app.get("/api/leaderboard/export")
def export_leaderboard(fmt: str = "csv", auth=Depends(require_auth)):
    """把"快速测试(模型可用性)"结果导出成 CSV 或 Markdown，方便甩给别人看而不用截图。"""
    if fmt not in ("csv", "md"):
        raise HTTPException(status_code=400, detail="fmt 只支持 csv 或 md")

    view = _build_quick_leaderboard_view()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    if fmt == "csv":
        import csv
        import io

        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["排名", "主机", "模型", "可用", "响应耗时(s)", "最近测试时间"])
        for r in view["ranked"]:
            writer.writerow([r["rank"], r["host"], r["model"], "是", r.get("elapsed") or "", r.get("last_tested") or ""])
        for r in view["failed"]:
            writer.writerow(["", r["host"], r["model"], "否", "", r.get("last_tested") or ""])
        content = "\ufeff" + buf.getvalue()  # 加 BOM，避免 Excel 打开中文乱码
        media_type = "text/csv"
        filename = f"leaderboard_quick_{ts}.csv"
    else:
        lines = [f"# 模型可用性排行榜导出（{ts}）", "", f"{view['label']}", ""]
        if view["ranked"]:
            lines.append("| 排名 | 主机 | 模型 | 响应耗时(s) | 最近测试 |")
            lines.append("|---|---|---|---|---|")
            for r in view["ranked"]:
                lines.append(f"| {r['rank']} | {r['host']} | {r['model']} | {r.get('elapsed') or ''} | {r.get('last_tested') or ''} |")
            lines.append("")
        if view["failed"]:
            lines.append("不可用：")
            for r in view["failed"]:
                lines.append(f"- {r['host']} · {r['model']}")
            lines.append("")
        content = "\n".join(lines)
        media_type = "text/markdown"
        filename = f"leaderboard_quick_{ts}.md"

    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ---------------------------------------------------------------------------
# 历史趋势数据：每次扫描完成后追加一条时间序列快照(JSONL，一行一条)，用于前端画趋势图。
# 所有读写都只针对硬编码的 HISTORY_FILE 这一个路径，不接受任何来自请求的文件名/路径参数，
# 防止被用来读取这个目录之外的其它文件(比如系统密码文件)或篡改成任意文件写入。
# ---------------------------------------------------------------------------


def _append_history_snapshot(view):
    """view: _build_leaderboard_view() 的返回值。summary 是每个分类的汇总数字；
    models 是排名前100的 主机+模型 各自的总耗时明细(数量截断，避免文件随主机/模型数量无限膨胀)，
    用于前端按"某个具体模型"画耗时趋势线，而不只是看整体汇总。"""
    summary = {}
    models_detail = {}
    for cat, data in view.items():
        ranked = data.get("ranked", [])
        failed = data.get("failed", [])
        elapsed_list = [r["elapsed_total"] for r in ranked if r.get("elapsed_total") is not None]
        summary[cat] = {
            "ranked_count": len(ranked),
            "failed_count": len(failed),
            "best_elapsed": min(elapsed_list) if elapsed_list else None,
            "avg_elapsed": round(sum(elapsed_list) / len(elapsed_list), 2) if elapsed_list else None,
        }
        models_detail[cat] = [
            {"host": r["host"], "model": r["model"], "elapsed_total": r["elapsed_total"]}
            for r in ranked[:100]
        ]
    record = {"ts": datetime.now().isoformat(timespec="seconds"), "categories": summary, "models": models_detail}
    with _history_lock:
        try:
            with open(HISTORY_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
        except Exception:
            pass
    _enforce_history_limits()


def _read_history_lines():
    if not HISTORY_FILE.exists():
        return []
    lines = []
    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    lines.append(json.loads(line))
                except Exception:
                    continue  # 跳过损坏的单行，不让整个历史读取失败
    except Exception:
        return []
    return lines


def _rewrite_history(records):
    with _history_lock:
        tmp = HISTORY_FILE.with_name(f".{HISTORY_FILE.name}.tmp.{os.getpid()}.{threading.get_ident()}")
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                for r in records:
                    f.write(json.dumps(r, ensure_ascii=False) + "\n")
            os.replace(tmp, HISTORY_FILE)
        except Exception:
            pass


def _history_file_size() -> int:
    try:
        return HISTORY_FILE.stat().st_size
    except Exception:
        return 0


def _enforce_history_limits():
    """按当前设置做定期清理：超过保留天数的记录删掉；文件超过大小上限则从最旧的开始删，
    直到降到限制以下，防止无限增长把服务器磁盘占满、拖垮宿主机。"""
    settings = _load_settings()
    hist_cfg = settings.get("history", {})
    if not hist_cfg.get("auto_cleanup_enabled", True):
        return

    retention_days = max(1, int(hist_cfg.get("retention_days", 180)))
    max_size_bytes = min(
        HISTORY_MAX_SIZE_BYTES_HARD_CAP,
        max(1, int(hist_cfg.get("max_size_mb", 50))) * 1024 * 1024,
    )

    records = _read_history_lines()
    if not records:
        return

    cutoff = datetime.now() - timedelta(days=retention_days)
    kept = []
    for r in records:
        try:
            ts = datetime.fromisoformat(r.get("ts", ""))
        except Exception:
            continue  # 时间戳解析不了的脏记录直接丢弃
        if ts >= cutoff:
            kept.append(r)
    changed = len(kept) != len(records)

    # 按天数过滤后仍然超过大小上限的话，从最旧的开始继续丢，直到低于上限
    if changed:
        _rewrite_history(kept)
    if _history_file_size() > max_size_bytes:
        while kept and _history_file_size() > max_size_bytes:
            kept = kept[1:]
            _rewrite_history(kept)


class HistoryDeleteIn(BaseModel):
    mode: str  # "days" | "all"
    days: int | None = None  # mode=="days" 时必填，比如 30/60/180/365


@app.get("/api/history/stats")
def history_stats(auth=Depends(require_auth)):
    records = _read_history_lines()
    return {
        "count": len(records),
        "size_bytes": _history_file_size(),
        "oldest_ts": records[0]["ts"] if records else None,
        "newest_ts": records[-1]["ts"] if records else None,
    }


@app.get("/api/history")
def get_history(days: int = 90, auth=Depends(require_auth)):
    """给趋势图用：默认只返回最近 90 天，避免一次性把全部历史都传给前端。"""
    records = _read_history_lines()
    if days > 0:
        cutoff = datetime.now() - timedelta(days=days)
        out = []
        for r in records:
            try:
                if datetime.fromisoformat(r.get("ts", "")) >= cutoff:
                    out.append(r)
            except Exception:
                continue
        return out
    return records


@app.get("/api/history/model")
def get_history_for_model(host: str, model: str, category: str = "core", days: int = 90, auth=Depends(require_auth)):
    """给"按模型看趋势"用：从历史快照里抽取指定 主机+模型+分类 的耗时序列。"""
    host = normalize_url(host)
    records = _read_history_lines()
    if days > 0:
        cutoff = datetime.now() - timedelta(days=days)
        records = [r for r in records if _ts_after(r.get("ts"), cutoff)]
    out = []
    for r in records:
        for entry in (r.get("models", {}) or {}).get(category, []):
            if entry.get("host") == host and entry.get("model") == model:
                out.append({"ts": r["ts"], "elapsed_total": entry.get("elapsed_total")})
                break
    return out


def _ts_after(ts, cutoff) -> bool:
    try:
        return datetime.fromisoformat(ts or "") >= cutoff
    except Exception:
        return False


@app.delete("/api/history")
def delete_history(body: HistoryDeleteIn, request: Request, auth=Depends(require_auth)):
    records = _read_history_lines()
    if body.mode == "all":
        _rewrite_history([])
        _record_audit(request, "history_delete", "all")
        return {"status": "ok", "remaining": 0}
    if body.mode == "days":
        if not body.days or body.days <= 0:
            raise HTTPException(status_code=400, detail="days 必须是正整数")
        cutoff = datetime.now() - timedelta(days=body.days)
        kept = []
        for r in records:
            try:
                ts = datetime.fromisoformat(r.get("ts", ""))
            except Exception:
                continue
            if ts >= cutoff:
                kept.append(r)
        _rewrite_history(kept)
        _record_audit(request, "history_delete", f"older_than_{body.days}_days")
        return {"status": "ok", "remaining": len(kept)}
    raise HTTPException(status_code=400, detail="mode 只支持 days 或 all")


# ---------------------------------------------------------------------------
# 只读分享链接：把排行榜以只读形式分享出去，不需要登录，但看不到主机地址/管理功能。
# 用独立的随机 token 做校验(不是登录 session)，token 在设置里生成/重置，enabled=false 时整个接口关闭。
# ---------------------------------------------------------------------------


def _build_public_leaderboard_view():
    """基于 _build_leaderboard_view() 做脱敏：主机地址替换成"主机N"匿名标签(同一次请求内地址->
    编号保持一致，方便看出"同一台机器的不同模型"，但看不到真实地址)，且不返回任何管理相关字段。"""
    view = _build_leaderboard_view()
    host_alias = {}

    def alias_for(host):
        if host not in host_alias:
            host_alias[host] = f"主机{len(host_alias) + 1}"
        return host_alias[host]

    public = {}
    for cat, data in view.items():
        ranked = [
            {
                "host": alias_for(r["host"]),
                "model": r["model"],
                "family_hint": r["family_hint"],
                "rank": r["rank"],
                "passed": r["passed"],
                "total": r["total"],
                "elapsed_total": r["elapsed_total"],
                "elapsed_avg": r["elapsed_avg"],
                "last_tested": r["last_tested"],
            }
            for r in data["ranked"]
        ]
        failed = [
            {
                "host": alias_for(r["host"]),
                "model": r["model"],
                "family_hint": r["family_hint"],
                "status": r["status"],
                "last_tested": r["last_tested"],
            }
            for r in data["failed"]
        ]
        public[cat] = {"label": data["label"], "ranked": ranked, "failed": failed}
    return public


@app.get("/api/share/settings")
def get_share_settings(auth=Depends(require_auth)):
    share = _load_settings().get("share", {})
    tokens = [t for t in share.get("tokens", []) if not _token_expired(t)]
    return {"enabled": share.get("enabled", False), "tokens": tokens}


def _token_expired(t: dict) -> bool:
    exp = t.get("expires_at")
    if not exp:
        return False
    try:
        return datetime.fromisoformat(exp) < datetime.now()
    except Exception:
        return False


class ShareSettingsIn(BaseModel):
    enabled: bool


@app.put("/api/share/settings")
def put_share_settings(body: ShareSettingsIn, request: Request, auth=Depends(require_auth)):
    with _settings_lock:
        raw = _load_json_file(SETTINGS_FILE, {})
        settings = _deep_merge_defaults(DEFAULT_SETTINGS, raw)
        settings["share"]["enabled"] = body.enabled
        _save_json_file(SETTINGS_FILE, settings)
    _record_audit(request, "share_settings_update", f"enabled={body.enabled}")
    return {"enabled": settings["share"]["enabled"]}


class ShareTokenCreateIn(BaseModel):
    label: str = ""
    expires_days: int | None = None  # 不填/None 表示永不过期


@app.post("/api/share/tokens")
def create_share_token(body: ShareTokenCreateIn, request: Request, auth=Depends(require_auth)):
    with _settings_lock:
        raw = _load_json_file(SETTINGS_FILE, {})
        settings = _deep_merge_defaults(DEFAULT_SETTINGS, raw)
        expires_at = None
        if body.expires_days and body.expires_days > 0:
            expires_at = (datetime.now() + timedelta(days=body.expires_days)).isoformat(timespec="seconds")
        entry = {
            "token": secrets.token_urlsafe(24),
            "label": (body.label or "").strip()[:100],
            "created_at": datetime.now().isoformat(timespec="seconds"),
            "expires_at": expires_at,
        }
        settings["share"]["tokens"].append(entry)
        _save_json_file(SETTINGS_FILE, settings)
    _record_audit(request, "share_token_create", entry["label"] or "(未命名)")
    return entry


@app.delete("/api/share/tokens/{token}")
def revoke_share_token(token: str, request: Request, auth=Depends(require_auth)):
    with _settings_lock:
        raw = _load_json_file(SETTINGS_FILE, {})
        settings = _deep_merge_defaults(DEFAULT_SETTINGS, raw)
        before = len(settings["share"]["tokens"])
        settings["share"]["tokens"] = [t for t in settings["share"]["tokens"] if t["token"] != token]
        changed = len(settings["share"]["tokens"]) != before
        if changed:
            _save_json_file(SETTINGS_FILE, settings)
    if not changed:
        raise HTTPException(status_code=404, detail="未找到该链接")
    _record_audit(request, "share_token_revoke", "")
    return {"status": "ok"}


@app.get("/api/public/leaderboard/{token}")
def public_leaderboard(token: str):
    """无需登录的只读入口。只暴露排行榜脱敏视图，不暴露主机地址、审计日志、设置等任何管理功能。"""
    share = _load_settings().get("share", {})
    if not share.get("enabled"):
        raise HTTPException(status_code=404, detail="分享链接未开启")
    matched = None
    for t in share.get("tokens", []):
        if secrets.compare_digest(token, t.get("token", "")):
            matched = t
            break
    if not matched or _token_expired(matched):
        raise HTTPException(status_code=404, detail="分享链接无效或已过期")
    return _build_public_leaderboard_view()


# ---------------------------------------------------------------------------
# Prometheus 抓取端点：无需登录 session，但需要单独配置的 token（URL 参数或 Bearer 头），
# enabled=false 时整个端点关闭。只暴露聚合数字，不暴露主机地址等敏感信息。
# ---------------------------------------------------------------------------


def _check_metrics_token(request: Request, token: str | None):
    cfg = _load_settings().get("metrics", {})
    if not cfg.get("enabled") or not cfg.get("token"):
        raise HTTPException(status_code=404, detail="metrics 未启用")
    provided = token
    if not provided:
        authz = request.headers.get("authorization", "")
        if authz.lower().startswith("bearer "):
            provided = authz[7:]
    if not provided or not secrets.compare_digest(provided, cfg.get("token", "")):
        raise HTTPException(status_code=401, detail="metrics token 无效")


@app.get("/api/metrics/settings")
def get_metrics_settings(auth=Depends(require_auth)):
    cfg = _load_settings().get("metrics", {})
    return {"enabled": cfg.get("enabled", False), "has_token": bool(cfg.get("token"))}


class MetricsSettingsIn(BaseModel):
    enabled: bool


@app.put("/api/metrics/settings")
def put_metrics_settings(body: MetricsSettingsIn, request: Request, auth=Depends(require_auth)):
    with _settings_lock:
        raw = _load_json_file(SETTINGS_FILE, {})
        settings = _deep_merge_defaults(DEFAULT_SETTINGS, raw)
        settings["metrics"]["enabled"] = body.enabled
        if body.enabled and not settings["metrics"].get("token"):
            settings["metrics"]["token"] = secrets.token_urlsafe(24)
        _save_json_file(SETTINGS_FILE, settings)
    _record_audit(request, "metrics_settings_update", f"enabled={body.enabled}")
    return {"enabled": settings["metrics"]["enabled"], "token": settings["metrics"]["token"] if body.enabled else None}


@app.post("/api/metrics/regenerate")
def regenerate_metrics_token(request: Request, auth=Depends(require_auth)):
    with _settings_lock:
        raw = _load_json_file(SETTINGS_FILE, {})
        settings = _deep_merge_defaults(DEFAULT_SETTINGS, raw)
        settings["metrics"]["token"] = secrets.token_urlsafe(24)
        _save_json_file(SETTINGS_FILE, settings)
    _record_audit(request, "metrics_token_regenerate", "")
    return {"enabled": settings["metrics"]["enabled"], "token": settings["metrics"]["token"]}


@app.get("/api/metrics")
def prometheus_metrics(request: Request, token: str | None = None):
    _check_metrics_token(request, token)
    hosts = load_hosts()
    view = _build_leaderboard_view()
    hist_records = _read_history_lines()

    lines = []

    def gauge(name, help_text, value, labels=""):
        lines.append(f"# HELP {name} {help_text}")
        lines.append(f"# TYPE {name} gauge")
        lines.append(f"{name}{labels} {value}")

    gauge("ollama_scanner_hosts_total", "已添加的主机数量", len(hosts))
    gauge("ollama_scanner_hosts_enabled", "已启用的主机数量", sum(1 for h in hosts if h.get("enabled", True)))
    gauge("ollama_scanner_scan_running", "当前是否有扫描正在进行(1/0)", 1 if state.running else 0)
    gauge("ollama_scanner_history_records_total", "历史趋势记录条数", len(hist_records))
    gauge("ollama_scanner_history_size_bytes", "历史趋势文件大小(字节)", _history_file_size())

    for cat, data in view.items():
        gauge("ollama_scanner_leaderboard_ranked", "该分类下全部通过并参与排名的 主机+模型 数量",
              len(data["ranked"]), labels=f'{{category="{cat}"}}')
        gauge("ollama_scanner_leaderboard_failed", "该分类下存在失败项的 主机+模型 数量",
              len(data["failed"]), labels=f'{{category="{cat}"}}')

    return Response(content="\n".join(lines) + "\n", media_type="text/plain; version=0.0.4")


class RetestIn(BaseModel):
    host: str
    model: str


@app.post("/api/leaderboard/retest")
def leaderboard_retest(body: RetestIn, auth=Depends(require_auth)):
    from scanner import quick_test  # 局部导入，避免和顶部导入顺序耦合

    host = normalize_url(body.host)
    model = body.model.strip()
    if not model:
        raise HTTPException(status_code=400, detail="模型名不能为空")

    viable, verr, _elapsed = quick_test(host, model)
    if not viable:
        with _leaderboard_lock:
            lb = _load_json_file(LEADERBOARD_FILE, [])
            lb_map = {f"{e['host']}|{e['model']}": e for e in lb}
            entry = lb_map.get(f"{host}|{model}", {})
            entry.update({
                "host": host,
                "model": model,
                "categories": {},
                "last_tested": datetime.now().isoformat(),
                "tests": [],
                "error": f"主机/模型不可达: {verr}",
            })
            lb_map[f"{host}|{model}"] = entry
            _save_json_file(LEADERBOARD_FILE, list(lb_map.values()))
        return entry

    tmp_state = ScanState()  # 独立状态，不与正在进行的全量扫描互相干扰
    refresh_custom_language_cases(_load_settings().get("custom_language_tests", []))
    refresh_custom_core_cases(_load_settings().get("custom_core_tests", []))
    set_test_categories_enabled(core=True, control=True, language=True, headless=True)
    raw_tests = run_advanced_tests(host, model, tmp_state)
    tests = [
        {
            "test": name,
            "category": category,
            "status": status,
            "detail": (str(detail)[:300] if detail else None),
            "elapsed": elapsed,
        }
        for name, category, status, detail, elapsed in raw_tests
    ]
    with _leaderboard_lock:
        lb = _load_json_file(LEADERBOARD_FILE, [])
        lb_map = {f"{e['host']}|{e['model']}": e for e in lb}
        entry = _merge_leaderboard_entry(lb_map, host, model, tests)
        _save_json_file(LEADERBOARD_FILE, list(lb_map.values()))
    return entry


class ModelTestIn(BaseModel):
    host: str
    model: str
    mode: str = "all"  # "all" | "quick" | "core" | "control" | "language" | "headless"


@app.post("/api/models/test")
def model_test(body: ModelTestIn, request: Request, auth=Depends(require_auth)):
    """统一入口：指挥中心每个排行榜每一行旁边的 6 个按钮都打这个接口，用 mode 区分具体测哪一种。
    quick/headless 只返回结果本身；core/control/language/all 会把结果并入排行榜持久化文件
    （只更新测到的那个分类，不影响其它分类的历史成绩，见 _merge_leaderboard_entry）。"""
    host = normalize_url(body.host)
    model = body.model.strip()
    if not model:
        raise HTTPException(status_code=400, detail="模型名不能为空")

    if body.mode == "quick":
        ok, err, elapsed = quick_test(host, model)
        _record_uptime_sample(host, model, ok)
        return {"mode": "quick", "host": host, "model": model, "ok": ok, "elapsed": elapsed, "error": err if not ok else None}

    if body.mode == "headless":
        tmp_state = ScanState()
        ok, details = run_headless_tests_only(host, model, tmp_state)
        return {"mode": "headless", "host": host, "model": model, "supported": ok, "details": details}

    if body.mode not in ("all", "core", "control", "language"):
        raise HTTPException(status_code=400, detail="mode 只支持 all/quick/core/control/language/headless")

    viable, verr, _elapsed = quick_test(host, model)
    if not viable:
        with _leaderboard_lock:
            lb = _load_json_file(LEADERBOARD_FILE, [])
            lb_map = {f"{e['host']}|{e['model']}": e for e in lb}
            entry = lb_map.get(f"{host}|{model}", {})
            entry.update({
                "host": host, "model": model,
                "last_tested": datetime.now().isoformat(),
                "error": f"主机/模型不可达: {verr}",
            })
            lb_map[f"{host}|{model}"] = entry
            _save_json_file(LEADERBOARD_FILE, list(lb_map.values()))
        return entry

    tmp_state = ScanState()
    refresh_custom_language_cases(_load_settings().get("custom_language_tests", []))
    refresh_custom_core_cases(_load_settings().get("custom_core_tests", []))
    if body.mode == "all":
        categories = None
        set_test_categories_enabled(core=True, control=True, language=True, headless=True)
    else:
        categories = [body.mode]
    raw_tests = run_advanced_tests(host, model, tmp_state, categories=categories)
    tests = [
        {
            "test": name, "category": category, "status": status,
            "detail": (str(detail)[:300] if detail else None), "elapsed": elapsed,
        }
        for name, category, status, detail, elapsed in raw_tests
    ]
    with _leaderboard_lock:
        lb = _load_json_file(LEADERBOARD_FILE, [])
        lb_map = {f"{e['host']}|{e['model']}": e for e in lb}
        entry = _merge_leaderboard_entry(lb_map, host, model, tests)
        _save_json_file(LEADERBOARD_FILE, list(lb_map.values()))
    return entry


# ---------------------------------------------------------------------------
# 侧边栏：每个主机 / 每个模型的连通性状态（绿色正常 / 红色失败），支持一键 Ping 重测
# ---------------------------------------------------------------------------


UPTIME_HISTORY_CAP = 100  # 每个 主机+模型 最多保留这么多条最近的在线/离线采样，避免文件无限增长


def _load_ping_status():
    return _load_json_file(PING_STATUS_FILE, {})


def _save_ping_status(host, model, result):
    with _ping_lock:
        status = _load_ping_status()
        key = f"{host}|{model}"
        entry = status.get(key, {})
        history = entry.get("history", [])
        history.append({"ok": bool(result.get("ok")), "ts": result.get("ts") or datetime.now().isoformat(timespec="seconds")})
        if len(history) > UPTIME_HISTORY_CAP:
            history = history[-UPTIME_HISTORY_CAP:]
        entry.update(result)
        entry["history"] = history
        status[key] = entry
        _save_json_file(PING_STATUS_FILE, status)


def _record_uptime_sample(host, model, ok):
    """扫描过程中的可用性结果也计入在线率采样，不影响"最近一次手动 Ping"这个字段本身。"""
    with _ping_lock:
        status = _load_ping_status()
        key = f"{host}|{model}"
        entry = status.setdefault(key, {})
        history = entry.get("history", [])
        history.append({"ok": bool(ok), "ts": datetime.now().isoformat(timespec="seconds")})
        if len(history) > UPTIME_HISTORY_CAP:
            history = history[-UPTIME_HISTORY_CAP:]
        entry["history"] = history
        _save_json_file(PING_STATUS_FILE, status)


def _uptime_pct(entry) -> float | None:
    history = (entry or {}).get("history") or []
    if not history:
        return None
    return round(100 * sum(1 for h in history if h.get("ok")) / len(history), 1)


@app.get("/api/hosts/status")
def hosts_status(auth=Depends(require_auth)):
    """给左侧栏用：每个主机 -> 已知模型列表 及 各自的连通性状态 + 最近样本的在线率。
    优先使用最近一次手动 Ping 的结果，没有 Ping 过则回退到最近一次扫描的可用性结果。"""
    hosts = load_hosts()
    results = _load_json_file(RESULTS_FILE, {})
    discovered = results.get("discovered", {})
    viability = results.get("viability", {})
    pings = _load_ping_status()

    out = []
    for h in hosts:
        url = h["url"]
        models = discovered.get(url, [])
        model_list = []
        for m in models:
            key = f"{url}|{m}"
            ping = pings.get(key)
            if ping and ping.get("ts"):
                ok = ping.get("ok")
                checked_at = ping.get("ts")
                source = "ping"
            else:
                ok = viability.get(key)
                checked_at = results.get("generated_at")
                source = "scan"
            model_list.append({
                "model": m,
                "ok": ok,
                "last_checked": checked_at,
                "source": source,
                "uptime_pct": _uptime_pct(ping),
            })
        model_list.sort(key=lambda m: (m["ok"] is not True, m["model"]))  # 在线的排前面
        out.append({
            "url": url,
            "enabled": h.get("enabled", True),
            "favorite": h.get("favorite", False),
            "last_scan_status": results.get("host_status", {}).get(url, "unknown"),
            "models": model_list,
        })
    return out


class PingIn(BaseModel):
    host: str
    model: str


@app.post("/api/ping")
def ping_model(body: PingIn, auth=Depends(require_auth)):
    """侧边栏点击模型时调用：发一条"你好"，只关心是否能收到正常回复。"""
    host = normalize_url(body.host)
    model = body.model.strip()
    if not model:
        raise HTTPException(status_code=400, detail="模型名不能为空")

    start = time.time()
    try:
        resp = requests.post(
            f"{host}/api/generate",
            json={"model": model, "prompt": "你好", "stream": False},
            timeout=20,
        )
        elapsed = round(time.time() - start, 2)
        data = resp.json()
        if "error" in data:
            result = {"ok": False, "error": str(data["error"])[:300], "elapsed": elapsed}
        else:
            reply = (data.get("response") or "").strip()
            result = {"ok": bool(reply), "reply": reply[:200], "elapsed": elapsed}
    except Exception as e:
        result = {"ok": False, "error": str(e)[:300], "elapsed": round(time.time() - start, 2)}

    result.update({"host": host, "model": model, "ts": datetime.now().isoformat()})
    _save_ping_status(host, model, result)
    return result


# ---------------------------------------------------------------------------
# 静态资源（login.html 不需要鉴权；index.html 走上面的 "/" 路由做了鉴权拦截）
# ---------------------------------------------------------------------------

class NoCacheStaticFiles(StaticFiles):
    """静态文件不做浏览器强缓存，每次都向服务器确认版本，
    避免重新部署后手机/浏览器还在用旧的 app.js / style.css。"""

    def file_response(self, *args, **kwargs):
        response = super().file_response(*args, **kwargs)
        response.headers["Cache-Control"] = "no-cache, must-revalidate"
        return response


static_dir = Path(__file__).parent.parent / "static"
app.mount("/", NoCacheStaticFiles(directory=str(static_dir), html=True), name="static")
