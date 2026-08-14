"""
Telegram Bot 交互菜单。

背景：原来的 _notify_telegram() 只会主动推送消息（sendMessage），从来没有调用过
setMyCommands，所以 Telegram 客户端左侧不会出现命令菜单——不是 bug，是这个能力
本来就没做。这个模块补上"能接收指令、能双向交互"这一半：

  /addhost  -> 进入等待模式，下一条消息整段丢进来，用和前端"批量粘贴"完全一致的
               正则从文本里抠 ip:port，私网地址直接加，公网地址要额外按确认键
               （对应前端那个 window.confirm 二次确认，Bot 场景下换成 inline 按钮）
  /scan     -> 弹一个 6 选 N 的 inline keyboard（对应界面上那 6 个测试类型开关），
               每按一下换一次勾选状态，最后点"开始扫描"才真正触发
  /status   -> 查看当前是否在跑、上次结果摘要
  /cancel   -> 清掉当前等待状态

设计上刻意不用 python-telegram-bot 这类重框架——回调面很小（几个命令 + 一种
inline keyboard），自己维护一个纯函数式的 handle_update() 更容易审查全部逻辑，
也不用额外拉一个大依赖。
"""
import hashlib
import hmac
import re
import time

import requests

TELEGRAM_API = "https://api.telegram.org"

# 和 static/app.js 里 IP_PORT_RE / isPrivateIp 保持同一套规则，
# 两边任何一边改了识别规则，另一边也要跟着改，否则用户会遇到
# "网页能识别、Bot 识别不出来"这种不一致体验。
IP_PORT_RE = re.compile(r"(?:https?://)?(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?")
DEFAULT_PORT = "11434"

TEST_CATEGORIES = [
    ("full", "1 全部功能测试"),
    ("quick", "🔒 2 快速在线测试"),
    ("core", "3 核心测试"),
    ("control", "4 控制性测试"),
    ("language", "5 语言测试"),
    ("headless", "6 🌐无头浏览器"),
]

# chat_id -> 会话状态。单管理员场景，进程内存足够，不需要落盘。
_sessions: dict[int, dict] = {}

# main.py 在启动时调用 configure() 注入这些依赖，避免 telegram_bot.py 反向 import main.py
# 造成循环引用——这个模块只通过下面这几个函数指针跟主程序打交道。
_deps = {
    "load_settings": None,      # () -> dict
    "add_host": None,           # (url, group, tags, force) -> (ok, code, message)
    "load_hosts": None,         # () -> list[dict]
    "get_scan_state": None,     # () -> ScanState
    "launch_scan": None,        # (hosts, concurrency, model_concurrency, **category_flags) -> bool
    "record_audit": None,       # (source: str, action: str, detail: str) -> None
}


def configure(**kwargs):
    _deps.update(kwargs)


def is_private_ip(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        nums = [int(p) for p in parts]
    except ValueError:
        return False
    if any(n < 0 or n > 255 for n in nums):
        return False
    a, b = nums[0], nums[1]
    if a == 10:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 192 and b == 168:
        return True
    if a == 127:
        return True
    if a == 169 and b == 254:
        return True
    return False


def parse_addresses(text: str):
    """从任意文本里抠出 ip[:port]，跟前端 parseAddresses() 是同一套规则的 Python 版本。"""
    seen = set()
    results = []
    for m in IP_PORT_RE.finditer(text or ""):
        ip = m.group(1)
        port = m.group(2) or DEFAULT_PORT
        url = f"http://{ip}:{port}"
        if url in seen:
            continue
        seen.add(url)
        results.append({"url": url, "ip": ip, "private": is_private_ip(ip)})
    return results


def _webhook_secret(bot_token: str) -> str:
    """从 bot_token 派生一个稳定但不直接暴露 token 本身的 URL path 片段。"""
    return hmac.new(b"ollama-scanner-tg-webhook", bot_token.encode(), hashlib.sha256).hexdigest()[:32]


def webhook_path(bot_token: str) -> str:
    return f"/api/telegram/webhook/{_webhook_secret(bot_token)}"


def _api_call(bot_token: str, method: str, payload: dict):
    resp = requests.post(f"{TELEGRAM_API}/bot{bot_token}/{method}", json=payload, timeout=10)
    resp.raise_for_status()
    return resp.json()


def send_message(bot_token: str, chat_id, text: str, reply_markup: dict | None = None):
    payload = {"chat_id": chat_id, "text": text}
    if reply_markup is not None:
        payload["reply_markup"] = reply_markup
    return _api_call(bot_token, "sendMessage", payload)


def answer_callback_query(bot_token: str, callback_query_id: str, text: str = ""):
    return _api_call(bot_token, "answerCallbackQuery", {"callback_query_id": callback_query_id, "text": text, "show_alert": False})


def edit_message_reply_markup(bot_token: str, chat_id, message_id, reply_markup: dict):
    return _api_call(bot_token, "editMessageReplyMarkup", {
        "chat_id": chat_id, "message_id": message_id, "reply_markup": reply_markup,
    })


BOT_COMMANDS = [
    {"command": "scan", "description": "选测试类型并开始一次扫描"},
    {"command": "addhost", "description": "添加主机地址（支持整段文本批量识别）"},
    {"command": "status", "description": "查看当前扫描状态"},
    {"command": "cancel", "description": "取消当前正在进行的操作"},
    {"command": "help", "description": "查看帮助"},
]


def sync_webhook_and_commands(tg_cfg: dict):
    """设置保存时调用：注册命令菜单（解决"左边没有菜单栏"）+ 注册 webhook（解决"收不到消息/不能交互"）。
    没填 public_base_url 时只注册命令菜单，webhook 留空——Bot 仍然只能推送通知，
    但至少菜单会出现，用户点了会看到"未部署交互功能"这种提示而不是完全没反应。
    任何一步失败都不应该让整个 /api/settings 保存请求跟着 500，所以调用方要包一层 try/except。"""
    bot_token = tg_cfg.get("bot_token", "")
    if not bot_token:
        return {"commands": False, "webhook": False}

    _api_call(bot_token, "setMyCommands", {"commands": BOT_COMMANDS})
    result = {"commands": True, "webhook": False}

    base_url = (tg_cfg.get("public_base_url") or "").rstrip("/")
    if base_url:
        secret_token = _webhook_secret(bot_token)
        _api_call(bot_token, "setWebhook", {
            "url": f"{base_url}{webhook_path(bot_token)}",
            "secret_token": secret_token,
            "allowed_updates": ["message", "callback_query"],
        })
        result["webhook"] = True
    else:
        # 没配公网地址就把 webhook 撤了，避免残留一个指向旧地址、Telegram 一直重试打不通的 webhook
        _api_call(bot_token, "deleteWebhook", {})
    return result


def _category_keyboard(selected: set) -> dict:
    rows = []
    for key, label in TEST_CATEGORIES:
        mark = "✅" if key in selected else "⬜"
        rows.append([{"text": f"{mark} {label}", "callback_data": f"cat:{key}"}])
    rows.append([
        {"text": "🚀 开始扫描", "callback_data": "scan:go"},
        {"text": "✖ 取消", "callback_data": "scan:cancel"},
    ])
    return {"inline_keyboard": rows}


def _hosts_summary_line(hosts) -> str:
    enabled = [h for h in hosts if h.get("enabled", True)]
    return f"当前主机列表共 {len(hosts)} 台，其中 {len(enabled)} 台参与扫描"


def _handle_command(chat_id, text: str, bot_token: str):
    cmd = text.split()[0].split("@")[0].lower()  # 群里可能是 /scan@xxx_bot 这种形式

    if cmd in ("/start", "/help"):
        _sessions.pop(chat_id, None)
        send_message(bot_token, chat_id,
            "🛰 Ollama 集群扫描台\n\n"
            "/scan — 选测试类型并开始一次扫描\n"
            "/addhost — 添加主机地址（可以直接整段粘贴，我会自动识别 ip:port）\n"
            "/status — 查看当前扫描状态\n"
            "/cancel — 取消当前正在进行的操作")
        return

    if cmd == "/cancel":
        had_session = _sessions.pop(chat_id, None) is not None
        send_message(bot_token, chat_id, "已取消当前操作。" if had_session else "当前没有进行中的操作。")
        return

    if cmd == "/addhost":
        _sessions[chat_id] = {"mode": "awaiting_hosts"}
        send_message(bot_token, chat_id,
            "请发一段包含主机地址的文本，可以是多行、也可以夹杂其他文字，"
            "我会自动识别里面的 ip:port（识别不到端口默认按 11434）。\n"
            "发 /cancel 可以随时退出。")
        return

    if cmd == "/status":
        state = _deps["get_scan_state"]()
        if state.running:
            send_message(bot_token, chat_id, "🟡 扫描正在进行中……发 /status 可以随时再查。")
        elif state.results:
            host_status = state.results.get("host_status", {})
            down = [h for h, s in host_status.items() if s != "ok"]
            msg = f"🟢 当前没有扫描在跑。上次结果：{len(host_status)} 台主机，{len(down)} 台异常。"
            if down:
                msg += "\n" + "\n".join(f"  · {h}" for h in down[:15])
            send_message(bot_token, chat_id, msg)
        else:
            send_message(bot_token, chat_id, "还没有跑过扫描。发 /scan 开始第一次。")
        return

    if cmd == "/scan":
        hosts = _deps["load_hosts"]()
        if not hosts:
            send_message(bot_token, chat_id, "主机列表是空的，先用 /addhost 加几台主机。")
            return
        selected = {"quick"}  # 默认勾选"快速在线测试"，和网页端扫描面板的默认项对齐
        _sessions[chat_id] = {"mode": "scan_config", "selected": selected}
        send_message(bot_token, chat_id,
            f"{_hosts_summary_line(hosts)}\n选测试类型（可多选），选好后点「开始扫描」：",
            reply_markup=_category_keyboard(selected))
        return

    send_message(bot_token, chat_id, "没认出这个命令，发 /help 看看支持哪些。")


def _handle_text_message(chat_id, text: str, bot_token: str):
    session = _sessions.get(chat_id)
    if not session or session.get("mode") != "awaiting_hosts":
        send_message(bot_token, chat_id, "发 /help 看看我能做什么。")
        return

    parsed = parse_addresses(text)
    if not parsed:
        send_message(bot_token, chat_id, "这段文本里没识别到任何 ip:port 地址，换一段再试，或发 /cancel 退出。")
        return

    private_ones = [p for p in parsed if p["private"]]
    public_ones = [p for p in parsed if not p["private"]]

    added, skipped = [], []
    for p in private_ones:
        ok, code, msg = _deps["add_host"](p["url"], "", [], False)
        (added if ok else skipped).append((p["url"], msg if not ok else None))

    lines = []
    if added:
        lines.append(f"✅ 已添加 {len(added)} 个内网地址：")
        lines.extend(f"  · {u}" for u, _ in added)
    if skipped:
        lines.append(f"⚠️ {len(skipped)} 个跳过（已存在/连不上）：")
        lines.extend(f"  · {u}（{m}）" for u, m in skipped)

    if public_ones:
        # 和前端批量粘贴一样：公网地址不能不问就加，必须显式确认"这是你自己有权测试的主机"。
        _sessions[chat_id] = {"mode": "confirm_public_hosts", "urls": [p["url"] for p in public_ones]}
        pub_list = "\n".join(f"  · {p['url']}" for p in public_ones)
        lines.append(
            f"\n⚠️ 另外识别到 {len(public_ones)} 个不属于内网网段的地址：\n{pub_list}\n\n"
            f"请确认这些都是你自己拥有或已获得明确授权测试的主机。"
        )
        send_message(bot_token, chat_id, "\n".join(lines), reply_markup={
            "inline_keyboard": [[
                {"text": "✅ 确认添加这些公网地址", "callback_data": "pubhost:confirm"},
                {"text": "✖ 不要，只保留内网的", "callback_data": "pubhost:reject"},
            ]]
        })
        return

    _sessions.pop(chat_id, None)
    send_message(bot_token, chat_id, "\n".join(lines) if lines else "没有新地址被添加。")


def _handle_callback_query(cq: dict, bot_token: str):
    chat_id = cq["message"]["chat"]["id"]
    message_id = cq["message"]["message_id"]
    data = cq.get("data", "")
    answer_callback_query(bot_token, cq["id"])  # 先应答，去掉 Telegram 客户端按钮上的转圈

    if data.startswith("cat:"):
        session = _sessions.get(chat_id)
        if not session or session.get("mode") != "scan_config":
            return
        key = data.split(":", 1)[1]
        selected = session["selected"]
        if key in selected:
            selected.discard(key)
        else:
            selected.add(key)
        edit_message_reply_markup(bot_token, chat_id, message_id, _category_keyboard(selected))
        return

    if data == "scan:cancel":
        _sessions.pop(chat_id, None)
        send_message(bot_token, chat_id, "已取消。")
        return

    if data == "scan:go":
        session = _sessions.get(chat_id)
        if not session or session.get("mode") != "scan_config":
            return
        selected = session["selected"]
        if not selected:
            send_message(bot_token, chat_id, "至少选一个测试类型再开始。")
            return
        _sessions.pop(chat_id, None)
        hosts = [h for h in _deps["load_hosts"]() if h.get("enabled", True)]
        # "全部功能测试"等价于核心+控制性+语言性+无头浏览器全开；
        # "快速在线测试"是最轻量的档位，不跑高级测试类别，只对齐现有扫描逻辑里的语义。
        flags = {
            "enable_core": "full" in selected or "core" in selected,
            "enable_control": "full" in selected or "control" in selected,
            "enable_language": "full" in selected or "language" in selected,
            "enable_headless": "full" in selected or "headless" in selected,
        }
        ok = _deps["launch_scan"](hosts, 3, 4, **flags)
        _deps["record_audit"]("telegram", "scan_start", f"chat_id={chat_id} categories={sorted(selected)}")
        send_message(bot_token, chat_id, "🚀 扫描已开始，完成后如果发现新异常我会再发一条通知。" if ok else "⚠️ 没能启动扫描（可能已经有一个在跑了）。")
        return

    if data == "pubhost:confirm":
        session = _sessions.get(chat_id)
        if not session or session.get("mode") != "confirm_public_hosts":
            return
        urls = session["urls"]
        _sessions.pop(chat_id, None)
        added, skipped = [], []
        for url in urls:
            ok, code, msg = _deps["add_host"](url, "", [], False)
            (added if ok else skipped).append((url, msg if not ok else None))
        lines = [f"✅ 已添加 {len(added)} 个公网地址："] + [f"  · {u}" for u, _ in added]
        if skipped:
            lines.append(f"⚠️ {len(skipped)} 个跳过：")
            lines.extend(f"  · {u}（{m}）" for u, m in skipped)
        send_message(bot_token, chat_id, "\n".join(lines))
        return

    if data == "pubhost:reject":
        _sessions.pop(chat_id, None)
        send_message(bot_token, chat_id, "好，公网地址没有添加。")
        return


def handle_update(update: dict, bot_token: str, allowed_chat_id: str):
    """处理一条 Telegram Update。只信任配置里指定的 chat_id，其它一律无视——
    Telegram webhook URL 一旦泄露，没有这层过滤的话任何人都能远程操作你的扫描台。"""
    message = update.get("message")
    callback_query = update.get("callback_query")

    if message is not None:
        chat_id = message.get("chat", {}).get("id")
        if str(chat_id) != str(allowed_chat_id):
            return
        text = message.get("text", "")
        if text.startswith("/"):
            _handle_command(chat_id, text, bot_token)
        else:
            _handle_text_message(chat_id, text, bot_token)
        return

    if callback_query is not None:
        chat_id = callback_query.get("message", {}).get("chat", {}).get("id")
        if str(chat_id) != str(allowed_chat_id):
            return
        _handle_callback_query(callback_query, bot_token)
        return
