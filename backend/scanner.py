"""
Ollama 集群扫描核心逻辑
改造自原始脚本: 支持动态主机列表 / 可中途停止 / 日志实时推送
"""
import requests
import re
import subprocess
import tempfile
import time
import json
import threading
import platform
import os
import random
from collections import defaultdict
from datetime import datetime

try:
    import resource  # 仅 Unix 可用，用于限制生成代码的资源消耗
except ImportError:
    resource = None

TIMEOUT = 120
QUICK_TEST_TIMEOUT = 20
CODE_RUN_TIMEOUT = 15

# 生成代码沙箱资源上限：防止模型生成的代码（例如被投毒/失控的模型）
# 消耗宿主机 CPU / 内存，或 fork 出大量进程（挖矿类滥用的典型特征）。
CODE_CPU_SECONDS = 10
CODE_MAX_MEMORY_BYTES = 512 * 1024 * 1024   # 512MB
# 注意: RLIMIT_NPROC 是按运行用户(uid)在全系统范围内计数的, 不是单进程独享,
# 高并发扫描时主程序自身会有较多线程, 这里给足余量避免误伤正常扫描, 但仍能挡住
# fork 炸弹式的挖矿/滥用代码 (试图瞬间拉起成百上千个子进程)。
CODE_MAX_PROCS = 512
CODE_MAX_FILE_BYTES = 10 * 1024 * 1024      # 10MB


def _limit_code_resources():
    """在子进程 exec 前调用（POSIX only），压低资源上限做纵深防御。
    注意：这不能替代真正的容器/命名空间隔离，只是尽量降低失控代码的破坏半径。"""
    if resource is None:
        return
    try:
        resource.setrlimit(resource.RLIMIT_CPU, (CODE_CPU_SECONDS, CODE_CPU_SECONDS))
        resource.setrlimit(resource.RLIMIT_AS, (CODE_MAX_MEMORY_BYTES, CODE_MAX_MEMORY_BYTES))
        resource.setrlimit(resource.RLIMIT_NPROC, (CODE_MAX_PROCS, CODE_MAX_PROCS))
        resource.setrlimit(resource.RLIMIT_FSIZE, (CODE_MAX_FILE_BYTES, CODE_MAX_FILE_BYTES))
    except Exception:
        pass

# =============================================================================
# 核心测试(category="core"): 生成代码 -> 沙箱子进程执行 -> 校验输出
# 相比早期版本大幅提高难度，覆盖算法/并发/字符串解析/数值边界四个方向的刁钻情形
# =============================================================================
CORE_TEST_CASES = [
    {
        "name": "Path Traversal Protection",
        "category": "core",
        "prompt": "write a Python function safe_read_file(base_dir, user_path) for a file manager panel. User passes relative path user_path, function should only allow reading files inside base_dir. If user_path tries to escape base_dir via ../, must raise PermissionError. For legal paths return file content as string. Return code only, no explanation, only import os.",
        "harness": """
import tempfile, os, shutil

tmpdir = tempfile.mkdtemp()
base = os.path.join(tmpdir, 'base')
os.makedirs(base)
outside = os.path.join(tmpdir, 'outside')
os.makedirs(outside)

with open(os.path.join(base, 'note.txt'), 'w') as f:
    f.write('hello inside')
with open(os.path.join(outside, 'secret.txt'), 'w') as f:
    f.write('TOP SECRET')

result1 = safe_read_file(base, 'note.txt')
assert result1 == 'hello inside', f"normal read failed: {result1!r}"

blocked = False
try:
    safe_read_file(base, '../outside/secret.txt')
except PermissionError:
    blocked = True
assert blocked, "SECURITY_FAIL: relative traversal NOT blocked!"

blocked2 = False
try:
    safe_read_file(base, os.path.join(outside, 'secret.txt'))
except PermissionError:
    blocked2 = True
assert blocked2, "SECURITY_FAIL: absolute traversal NOT blocked!"

shutil.rmtree(tmpdir)
print("ALL_PASS")
""",
        "expected": "ALL_PASS",
    },
    {
        "name": "Thread-Safe LRU Cache",
        "category": "core",
        "prompt": "Write a thread-safe Python class LRUCache(capacity) used as a caching layer accessed by multiple worker threads concurrently. Methods: get(key) returns the value or -1 if missing, and must mark the key as most recently used; put(key, value) inserts/updates the value and marks it as most recently used, evicting the Least Recently Used entry when size would exceed capacity. Must be safe under concurrent access from many threads at once (use proper locking, no race conditions or deadlocks). Return code only, no explanation, only standard library (threading/collections allowed).",
        "harness": """
import threading

cache = LRUCache(2)
cache.put(1, 'a')
cache.put(2, 'b')
assert cache.get(1) == 'a', "basic get failed"
cache.put(3, 'c')  # capacity=2, key 1 was just accessed so key 2 is LRU and must be evicted
assert cache.get(2) == -1, "LRU eviction order wrong: key 2 should have been evicted"
assert cache.get(1) == 'a'
assert cache.get(3) == 'c'

cache2 = LRUCache(50)
errors = []

def worker(base):
    try:
        for i in range(300):
            k = (base + i) % 50
            cache2.put(k, base * 1000 + i)
            cache2.get(k)
    except Exception as e:
        errors.append(repr(e))

threads = [threading.Thread(target=worker, args=(t,)) for t in range(8)]
for t in threads:
    t.start()
for t in threads:
    t.join(timeout=8)
assert not any(t.is_alive() for t in threads), "DEADLOCK_FAIL: worker thread did not finish (possible deadlock)"
assert not errors, f"concurrency errors: {errors}"
print("ALL_PASS")
""",
        "expected": "ALL_PASS",
    },
    {
        "name": "Quoted CSV Field Parser",
        "category": "core",
        "prompt": "Write a Python function parse_csv_line(line) implementing RFC4180-style CSV parsing for a single line: fields are separated by commas; a field may be wrapped in double quotes to contain literal commas; inside a quoted field, two consecutive double quotes represent one literal escaped double quote character; return a list of field strings with quoting/escaping resolved (quotes removed, escaped quotes unescaped). An empty line should return ['']. Return code only, no explanation, only standard library.",
        "harness": """
tests = [
    ('a,b,c', ['a', 'b', 'c']),
    ('"a,b",c,"d""e"', ['a,b', 'c', 'd"e']),
    ('a,,c', ['a', '', 'c']),
    ('"quoted only"', ['quoted only']),
    ('"a""b""c"', ['a"b"c']),
    ('', ['']),
    ('x,"",y', ['x', '', 'y']),
]
for line, expected in tests:
    got = parse_csv_line(line)
    assert got == expected, f"line={line!r} expected={expected!r} got={got!r}"
print("ALL_PASS")
""",
        "expected": "ALL_PASS",
    },
    {
        "name": "Precision-Safe Average",
        "category": "core",
        "prompt": "Write a Python function safe_average(values) for a billing/metering system. values is a list that may contain ints, floats, and None (None means a missing reading and must be skipped/ignored). Round the final result to 2 decimal places using Python's built-in round() (banker's rounding). If, after ignoring None entries, there are zero numeric values left (including on an empty input list), raise ValueError. If any element is not an int, float, or None (e.g. a string or list), raise TypeError. Return code only, no explanation, only standard library.",
        "harness": """
assert safe_average([1, 2, 3]) == 2.0
assert safe_average([10, None, 20, None]) == 15.0
assert safe_average([1, 2, 2]) == round(5 / 3, 2)

try:
    safe_average([])
    assert False, "empty list should raise ValueError"
except ValueError:
    pass

try:
    safe_average([None, None])
    assert False, "all-None input should raise ValueError"
except ValueError:
    pass

try:
    safe_average([1, "2", 3])
    assert False, "non-numeric element should raise TypeError"
except TypeError:
    pass

print("ALL_PASS")
""",
        "expected": "ALL_PASS",
    },
    {
        "name": "Mini Regex Engine (. and *)",
        "category": "core",
        "prompt": "Write a Python function is_match(s, p) that implements regular expression matching supporting '.' (matches any single character) and '*' (matches zero or more of the immediately preceding element), similar to the classic full-string regex matching problem. The ENTIRE string s must match the ENTIRE pattern p (not a substring match). Return True/False. Return code only, no explanation, only standard library.",
        "harness": """
cases = [
    ("aa", "a", False),
    ("aa", "a*", True),
    ("ab", ".*", True),
    ("aab", "c*a*b", True),
    ("mississippi", "mis*is*p*.", False),
    ("", "", True),
    ("", "a*", True),
    ("aaa", "a*a", True),
    ("ab", ".*c", False),
]
for s, p, expected in cases:
    got = is_match(s, p)
    assert got == expected, f"is_match({s!r},{p!r}) expected {expected} got {got}"
print("ALL_PASS")
""",
        "expected": "ALL_PASS",
    },
    {
        "name": "Sliding Window Rate Limiter",
        "category": "core",
        "prompt": "Write a Python class SlidingWindowRateLimiter(max_requests, window_seconds) for an API gateway using the sliding-window-log algorithm. Method allow(now) takes an explicit timestamp (float seconds) — do NOT call time.time() internally, only use the passed-in now value. Return True and record the request if there are fewer than max_requests recorded requests within the time window (now - window_seconds, now], otherwise return False without recording it. Return code only, no explanation, only standard library.",
        "harness": """
rl = SlidingWindowRateLimiter(3, 10)
timeline = [
    (0.0, True), (1.0, True), (2.0, True), (3.0, False),
    (10.1, True), (10.2, False), (11.5, True), (12.1, True),
]
for now, expected in timeline:
    got = rl.allow(now)
    assert got == expected, f"allow({now}) expected {expected} got {got}"
print("ALL_PASS")
""",
        "expected": "ALL_PASS",
    },
    {
        "name": "Topological Sort with Cycle Detection",
        "category": "core",
        "prompt": "Write a Python function topo_sort(num_nodes, edges) for a build-dependency system. num_nodes is an int (nodes are ids 0..num_nodes-1). edges is a list of (a, b) tuples meaning a must come before b. Return a valid topological order as a list containing ALL node ids (including nodes with no edges at all). If the graph contains a cycle, raise ValueError. Return code only, no explanation, only standard library.",
        "harness": """
def check_valid(order, n, edges):
    assert sorted(order) == list(range(n)), f"not a valid permutation of 0..{n-1}: {order}"
    pos = {v: i for i, v in enumerate(order)}
    for a, b in edges:
        assert pos[a] < pos[b], f"edge {a}->{b} violated in order {order}"

check_valid(topo_sort(3, [(0, 1), (1, 2)]), 3, [(0, 1), (1, 2)])
check_valid(topo_sort(5, [(0, 1), (0, 2), (1, 3), (2, 3), (3, 4)]), 5, [(0, 1), (0, 2), (1, 3), (2, 3), (3, 4)])
check_valid(topo_sort(4, []), 4, [])  # 无边孤立节点也必须全部出现

try:
    topo_sort(3, [(0, 1), (1, 2), (2, 0)])
    assert False, "3-node cycle should raise ValueError"
except ValueError:
    pass

try:
    topo_sort(2, [(0, 1), (1, 0)])
    assert False, "2-node cycle should raise ValueError"
except ValueError:
    pass

print("ALL_PASS")
""",
        "expected": "ALL_PASS",
    },
]


# =============================================================================
# 语言性测试(category="language"): 不涉及代码执行，直接用规则对模型的原始文字
# 输出做客观判定（字数/JSON结构/关键词次数/格式），避免主观打分
# =============================================================================

def _check_exact_han_count(response, n=20):
    han_chars = re.findall(r"[\u4e00-\u9fff]", response or "")
    count = len(han_chars)
    return count == n, f"汉字数={count}（要求恰好{n}个）"


def _check_json_person(response, *_):
    text = (response or "").strip()
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if not m:
        return False, "未在回复中找到JSON对象"
    try:
        obj = json.loads(m.group(0))
    except Exception as e:
        return False, f"JSON解析失败: {e}"
    if not isinstance(obj, dict) or set(obj.keys()) != {"name", "age", "city"}:
        return False, f"字段不符合要求(应且仅应有name/age/city): {list(obj.keys()) if isinstance(obj, dict) else obj}"
    if not isinstance(obj.get("age"), (int, float)) or isinstance(obj.get("age"), bool):
        return False, f"age 应为数字类型, 实际: {obj.get('age')!r}"
    if "28" not in str(obj.get("age")):
        return False, f"age 内容不正确: {obj.get('age')}"
    if "京" not in str(obj.get("city", "")):
        return False, f"city 内容不正确: {obj.get('city')}"
    return True, None


def _check_keyword_constraint(response, *_):
    text = response or ""
    count_backup = text.count("备份")
    if "删除" in text:
        return False, "出现了禁用词“删除”"
    if count_backup != 3:
        return False, f"“备份”出现了{count_backup}次（要求恰好3次）"
    return True, None


def _check_numbered_list(response, *_):
    lines = [l.strip() for l in (response or "").strip().split("\n") if l.strip()]
    numbered = []
    for l in lines:
        m = re.match(r"^(\d+)[\.\、]\s*(.+)$", l)
        if m:
            numbered.append(int(m.group(1)))
    if len(numbered) != 5:
        return False, f"编号行数量为{len(numbered)}（要求恰好5条）"
    if numbered != [1, 2, 3, 4, 5]:
        return False, f"编号顺序不正确: {numbered}"
    return True, None


def _check_generic_rules(response, rules):
    """给用户自定义"语言性测试用例"用的通用规则校验器。rules 是一个规则列表，
    全部通过才算 PASS。只做纯文本规则判定，不执行任何代码，风险和内置的语言性测试一致。
    支持的规则类型：
      - {"type": "exact_han_count", "n": 20}          恰好 n 个汉字
      - {"type": "keyword_count", "word": "备份", "count": 3}   某词恰好出现 count 次
      - {"type": "forbidden_words", "words": ["删除"]}          不能出现这些词
      - {"type": "numbered_list_count", "n": 5}        恰好 n 条 "数字. " 开头的编号行
      - {"type": "max_length", "n": 200}                回复长度不超过 n 个字符
    """
    text = response or ""
    for rule in rules or []:
        rtype = rule.get("type")
        if rtype == "exact_han_count":
            count = len(re.findall(r"[\u4e00-\u9fff]", text))
            if count != rule.get("n", 0):
                return False, f"汉字数={count}（要求恰好{rule.get('n', 0)}个）"
        elif rtype == "keyword_count":
            word = rule.get("word", "")
            actual = text.count(word) if word else 0
            if actual != rule.get("count", 0):
                return False, f"“{word}”出现了{actual}次（要求恰好{rule.get('count', 0)}次）"
        elif rtype == "forbidden_words":
            for w in rule.get("words", []):
                if w and w in text:
                    return False, f"出现了禁用词“{w}”"
        elif rtype == "numbered_list_count":
            lines = [l.strip() for l in text.strip().split("\n") if l.strip()]
            numbered = []
            for l in lines:
                m = re.match(r"^(\d+)[\.\、]\s*(.+)$", l)
                if m:
                    numbered.append(int(m.group(1)))
            n = rule.get("n", 0)
            if len(numbered) != n or numbered != list(range(1, n + 1)):
                return False, f"编号行不符合要求(实际{len(numbered)}条，要求{n}条且从1开始连续编号)"
        elif rtype == "max_length":
            if len(text) > rule.get("n", 10**9):
                return False, f"长度{len(text)}超过上限{rule.get('n')}"
    return True, None


def build_custom_language_case(defn: dict):
    """把一条用户自定义定义({"name","prompt","rules":[...]})转换成内部测试用例格式。"""
    rules = defn.get("rules", [])
    return {
        "name": f"[自定义] {defn.get('name', '未命名用例')}",
        "category": "language",
        "kind": "language",
        "prompt": defn.get("prompt", ""),
        "checker": lambda response, *_: _check_generic_rules(response, rules),
    }


# 运行时可由 main.py 根据设置里的自定义用例刷新，不需要重启进程。
CUSTOM_LANGUAGE_TEST_CASES = []
CUSTOM_CORE_TEST_CASES = []


def refresh_custom_language_cases(defs: list):
    global CUSTOM_LANGUAGE_TEST_CASES
    CUSTOM_LANGUAGE_TEST_CASES = [build_custom_language_case(d) for d in (defs or []) if d.get("prompt")]


def refresh_custom_core_cases(defs: list):
    """自定义"核心测试"：和内置 core 用例一样，会把 harness 拼到模型生成的代码后面，
    在沙箱子进程里执行。这是执行任意代码，因此新增时要求二次输入密码确认(见 main.py)，
    这里只负责把已经通过密码校验、存进设置里的定义转换成可执行的用例格式。"""
    global CUSTOM_CORE_TEST_CASES
    CUSTOM_CORE_TEST_CASES = [
        {
            "name": f"[自定义] {d.get('name', '未命名用例')}",
            "category": "core",
            "kind": "core",
            "prompt": d.get("prompt", ""),
            "harness": d.get("harness", ""),
            "expected": d.get("expected", "ALL_PASS"),
        }
        for d in (defs or []) if d.get("prompt") and d.get("harness")
    ]


LANGUAGE_TEST_CASES = [
    {
        "name": "严格字数约束摘要",
        "category": "language",
        "kind": "language",
        "prompt": "请用恰好20个汉字（不多不少，不计标点符号）介绍“光合作用”的基本原理。只输出这句话本身，不要输出编号、引号或其他任何说明文字。",
        "checker": _check_exact_han_count,
    },
    {
        "name": "结构化JSON抽取",
        "category": "language",
        "kind": "language",
        "prompt": "请把下面这句话转换成JSON对象：“小明今年28岁，住在北京”。JSON必须且只能包含这三个字段：name（字符串）、age（数字）、city（字符串）。只输出合法的JSON本身，不要输出任何其他文字或代码块标记。",
        "checker": _check_json_person,
    },
    {
        "name": "关键词次数与禁用词约束",
        "category": "language",
        "kind": "language",
        "prompt": "写一段关于“数据库备份”的说明文字，要求：全文必须恰好出现“备份”这个词3次（不多不少），并且全文不能出现“删除”这个词。只输出这段文字本身。",
        "checker": _check_keyword_constraint,
    },
    {
        "name": "严格编号列表格式",
        "category": "language",
        "kind": "language",
        "prompt": "列出恰好5条关于“如何提高代码可读性”的建议，格式要求：每条必须以“数字. ”开头（例如“1. ”），从1到5依次编号，每条一行，不要有标题、总结或多余空行。",
        "checker": _check_numbered_list,
    },
]


# =============================================================================
# 控制性测试(category="control"): 模拟 Hermes Agent / OpenClaw 这类 agent 框架
# 实际驱动模型的方式 —— 通过 Ollama /api/chat 的标准 tools / tool_calls 协议
# 发起工具调用，而不是像 core 测试那样直接生成一整段代码。
#
# 工具调用会在一个每次测试独立、结束即销毁的沙箱临时目录里真实执行读写，
# 用来区分"模型真的发起了工具调用并操作了文件" 和 "模型只是在文字里假装完成了"。
# 执行权限全程留在扫描服务器自己的沙箱目录内，不会涉及主机列表里的任何目标机器。
# =============================================================================

AGENT_SYSTEM_PROMPT = (
    "你是一个可以使用工具的助手。可用工具: read_file(读取文件内容)、write_file(写入文件内容)、"
    "list_dir(列出目录下的文件名)，全部只能操作当前工作目录内的相对路径。"
    "当任务需要读取或写入文件时，你必须通过调用对应工具真正完成操作，禁止在没有调用工具的情况下"
    "凭空编造文件内容或假装已经完成了操作。"
)

FS_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "读取指定相对路径文件的文本内容",
            "parameters": {
                "type": "object",
                "properties": {"path": {"type": "string", "description": "相对文件路径"}},
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "write_file",
            "description": "把文本内容写入指定相对路径的文件（会覆盖已有内容，不存在则创建）",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "相对文件路径"},
                    "content": {"type": "string", "description": "要写入的文本内容"},
                },
                "required": ["path", "content"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_dir",
            "description": "列出指定相对目录下的所有文件名，不传path则列出当前目录",
            "parameters": {
                "type": "object",
                "properties": {"path": {"type": "string", "description": "相对目录路径，默认为当前目录"}},
            },
        },
    },
]


def _safe_join(base_dir, rel_path):
    """把工具调用传入的相对路径解析到沙箱目录内，越权路径直接拒绝"""
    rel_path = rel_path or "."
    target = os.path.normpath(os.path.join(base_dir, rel_path))
    base_norm = os.path.normpath(base_dir)
    if target != base_norm and not target.startswith(base_norm + os.sep):
        raise ValueError(f"路径越权，禁止访问沙箱外的路径: {rel_path}")
    return target


def _make_tool_executor(sandbox_dir, call_log):
    """构造在沙箱目录内真实执行 read_file/write_file/list_dir 的执行器，并记录调用日志用于判分"""

    def executor(name, args):
        call_log.append((name, args if isinstance(args, dict) else {}))
        try:
            if name == "read_file":
                path = _safe_join(sandbox_dir, args.get("path", ""))
                if not os.path.isfile(path):
                    return f"ERROR: 文件不存在: {args.get('path')}"
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    return f.read()[:2000]
            elif name == "write_file":
                path = _safe_join(sandbox_dir, args.get("path", ""))
                os.makedirs(os.path.dirname(path) or sandbox_dir, exist_ok=True)
                with open(path, "w", encoding="utf-8") as f:
                    f.write(str(args.get("content", "")))
                return "OK: 写入成功"
            elif name == "list_dir":
                path = _safe_join(sandbox_dir, args.get("path", "."))
                if not os.path.isdir(path):
                    return f"ERROR: 目录不存在: {args.get('path')}"
                return json.dumps(sorted(os.listdir(path)), ensure_ascii=False)
            else:
                return f"ERROR: 未知工具: {name}"
        except ValueError as e:
            return f"ERROR: {e}"
        except Exception as e:
            return f"ERROR: {e}"

    return executor


def _build_read_config_prompt(sandbox):
    token = str(random.randint(1000, 9999))
    with open(os.path.join(sandbox, "server.conf"), "w", encoding="utf-8") as f:
        f.write(f"host=127.0.0.1\nmax_connections={token}\ntimeout=30\n")
    prompt = "请读取当前目录下的 server.conf 文件，告诉我 max_connections 的值。只回答这个数字本身，不要输出其他文字。"
    return prompt, {"token": token}


def _check_read_config(call_log, final_text, sandbox, context):
    if not any(c[0] == "read_file" for c in call_log):
        return False, "CONTROL_FAIL: 没有发起 read_file 工具调用，回答可能是凭空编造的"
    token = context["token"]
    if token not in (final_text or ""):
        return False, f"最终回答未包含正确的值 {token}: {str(final_text)[:150]}"
    return True, None


def _build_write_prompt(sandbox):
    marker = f"ready-{random.randint(1000, 9999)}"
    prompt = (
        f"请创建一个名为 status.txt 的文件，内容必须是：{marker}"
        "（只写这段文本本身，不要加引号或其他多余字符），完成后回复我“已完成”。"
    )
    return prompt, {"marker": marker}


def _check_write(call_log, final_text, sandbox, context):
    if not any(c[0] == "write_file" for c in call_log):
        return False, "CONTROL_FAIL: 没有发起 write_file 工具调用，模型可能只是嘴上说完成了但并未真正写入"
    path = os.path.join(sandbox, "status.txt")
    if not os.path.isfile(path):
        return False, "CONTROL_FAIL: 磁盘上并未生成 status.txt 文件"
    with open(path, "r", encoding="utf-8") as f:
        content = f.read().strip()
    marker = context["marker"]
    if marker not in content:
        return False, f"文件内容不符: 期望包含 '{marker}', 实际是 '{content[:100]}'"
    return True, None


def _build_multi_step_prompt(sandbox):
    token = f"token-{random.randint(100000, 999999)}"
    with open(os.path.join(sandbox, "a.log"), "w", encoding="utf-8") as f:
        f.write("普通日志内容，无关紧要")
    with open(os.path.join(sandbox, "b.log"), "w", encoding="utf-8") as f:
        f.write("另一份日志内容，同样无关紧要")
    with open(os.path.join(sandbox, "secret_notes.txt"), "w", encoding="utf-8") as f:
        f.write(token)
    prompt = "请先列出当前目录下的所有文件，然后读取文件名中包含“secret”的那个文件，把它的内容原样告诉我。"
    return prompt, {"token": token}


def _check_multi_step(call_log, final_text, sandbox, context):
    names_called = [c[0] for c in call_log]
    if "list_dir" not in names_called:
        return False, "CONTROL_FAIL: 没有先列目录就直接猜测文件名，不符合先探索后操作的agent流程"
    read_calls = [c for c in call_log if c[0] == "read_file"]
    if not read_calls:
        return False, "CONTROL_FAIL: 没有发起 read_file 工具调用"
    if not any("secret" in str(c[1].get("path", "")) for c in read_calls):
        got = [c[1].get("path") for c in read_calls]
        return False, f"没有读取到正确的文件(文件名应包含secret), 实际读取了: {got}"
    if context["token"] not in (final_text or ""):
        return False, f"最终回答未包含正确内容 {context['token']}: {str(final_text)[:150]}"
    return True, None


BROWSER_SYSTEM_PROMPT = (
    "你是一个可以操作无头浏览器的助手。可用工具: browser_navigate(跳转到指定URL)、"
    "browser_get_text(获取当前页面的文本内容)、browser_click_link(点击当前页面里的一个链接文字，"
    "会跳转到该链接指向的页面)。"
    "你必须通过真实调用这些工具来浏览网页获取信息，禁止在没有调用工具的情况下凭空编造页面内容。"
)

BROWSER_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "browser_navigate",
            "description": "让无头浏览器跳转到指定 URL 并返回该页面的文本内容",
            "parameters": {
                "type": "object",
                "properties": {"url": {"type": "string", "description": "要访问的完整 URL"}},
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "browser_get_text",
            "description": "获取无头浏览器当前所在页面的文本内容",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "browser_click_link",
            "description": "点击当前页面里文字完全匹配的一个链接，跳转到它指向的页面并返回新页面文本",
            "parameters": {
                "type": "object",
                "properties": {"link_text": {"type": "string", "description": "要点击的链接文字，需和页面上的完全一致"}},
                "required": ["link_text"],
            },
        },
    },
]


def _make_browser_tool_executor(pages: dict, entry_url: str, call_log: list):
    """构造一个纯内存的假"无头浏览器"：不发起任何真实网络请求，pages 是 url -> {"text","links"} 的字典。
    这样测试的是"模型能不能正确编排 navigate/click/get_text 这几个工具调用"，跟真实浏览器实现无关，
    也不需要真的装 Selenium/Playwright 或联网。"""
    browser_state = {"current_url": entry_url}

    def executor(name, args):
        call_log.append((name, args if isinstance(args, dict) else {}))
        try:
            if name == "browser_navigate":
                url = (args.get("url") or "").strip()
                page = pages.get(url)
                if not page:
                    return f"ERROR: 无法访问该URL(不存在): {url}"
                browser_state["current_url"] = url
                return page["text"]
            elif name == "browser_get_text":
                page = pages.get(browser_state["current_url"])
                return page["text"] if page else "ERROR: 当前页面不存在"
            elif name == "browser_click_link":
                page = pages.get(browser_state["current_url"])
                if not page:
                    return "ERROR: 当前页面不存在"
                link_text = (args.get("link_text") or "").strip()
                target = (page.get("links") or {}).get(link_text)
                if not target:
                    return f"ERROR: 当前页面没有名为“{link_text}”的链接，可用链接: {list((page.get('links') or {}).keys())}"
                browser_state["current_url"] = target
                return pages[target]["text"]
            else:
                return f"ERROR: 未知工具: {name}"
        except Exception as e:
            return f"ERROR: {e}"

    return executor


def run_headless_browser_task(host, model, task, state, tag="", max_turns=6):
    """跟 run_agent_tool_task 是同一套思路：用标准 /api/chat + tools 协议，
    看模型能不能真正编排"跳转→点击→读取文本"这几步来完成任务，而不是凭空编造答案。"""
    pages, entry_url, context = task["build_pages"]()
    call_log = []
    executor = _make_browser_tool_executor(pages, entry_url, call_log)

    messages = [
        {"role": "system", "content": BROWSER_SYSTEM_PROMPT},
        {"role": "user", "content": f"起始页面是 {entry_url}\n\n{task['task_text']}"},
    ]

    final_text = None
    error = None
    for _ in range(max_turns):
        if state.is_stopping():
            error = "收到停止信号"
            break
        msg, err = query_model_chat(host, model, messages, tools=BROWSER_TOOLS)
        if err:
            error = err
            break

        tool_calls = msg.get("tool_calls") or []
        content = msg.get("content", "") or ""
        assistant_msg = {"role": "assistant", "content": content}
        if tool_calls:
            assistant_msg["tool_calls"] = tool_calls
        messages.append(assistant_msg)

        if not tool_calls:
            final_text = content
            break

        for call in tool_calls:
            fn = (call or {}).get("function", {}) or {}
            name = fn.get("name")
            raw_args = fn.get("arguments", {})
            if isinstance(raw_args, str):
                try:
                    raw_args = json.loads(raw_args) if raw_args else {}
                except Exception:
                    raw_args = {}
            if not isinstance(raw_args, dict):
                raw_args = {}
            result = executor(name, raw_args)
            messages.append({"role": "tool", "content": str(result)})
    else:
        error = error or "达到最大对话轮数仍未给出最终答案"

    if final_text is None and error:
        state.log(f"{tag} 无头浏览器任务失败: {error}")
        return "REQUEST_FAIL", error

    try:
        ok, detail = task["check"](call_log, final_text or "", context)
    except Exception as e:
        ok, detail = False, f"判定过程异常: {e}"
    if not ok:
        state.log(f"{tag} 无头浏览器任务判定失败: {detail}")
    return ("PASS" if ok else "WRONG_OUTPUT"), detail


def _build_browser_single_hop_pages():
    price = random.randint(100, 999)
    home_url = "fake://shop.local/"
    product_url = "fake://shop.local/product"
    pages = {
        home_url: {
            "text": "欢迎来到示例商店首页。这里有一个链接可以查看商品详情。",
            "links": {"查看商品详情": product_url},
        },
        product_url: {
            "text": f"商品详情页。这款商品的价格是 {price} 元。",
            "links": {},
        },
    }
    return pages, home_url, {"price": str(price)}


def _check_browser_single_hop(call_log, final_text, context):
    names = [c[0] for c in call_log]
    if "browser_click_link" not in names and "browser_navigate" not in names:
        return False, "HEADLESS_FAIL: 没有真正调用跳转/点击工具，回答可能是凭空编造的"
    if context["price"] not in (final_text or ""):
        return False, f"最终回答未包含正确价格 {context['price']}: {str(final_text)[:150]}"
    return True, None


def _build_browser_multi_hop_pages():
    code = f"C{random.randint(1000, 9999)}"
    home_url = "fake://shop.local/"
    category_url = "fake://shop.local/category"
    product_url = "fake://shop.local/category/product"
    pages = {
        home_url: {
            "text": "欢迎来到示例商店首页，这里有多个分类入口。",
            "links": {"进入电子产品分类": category_url},
        },
        category_url: {
            "text": "电子产品分类页，这里列出了几款商品。",
            "links": {"查看无线耳机详情": product_url},
        },
        product_url: {
            "text": f"无线耳机详情页。优惠码是: {code}",
            "links": {},
        },
    }
    return pages, home_url, {"code": code}


def _check_browser_multi_hop(call_log, final_text, context):
    nav_or_click = [c for c in call_log if c[0] in ("browser_navigate", "browser_click_link")]
    if len(nav_or_click) < 2:
        return False, "HEADLESS_FAIL: 少于2次跳转，任务要求从首页经过分类页才能到详情页"
    if context["code"] not in (final_text or ""):
        return False, f"最终回答未包含正确优惠码 {context['code']}: {str(final_text)[:150]}"
    return True, None


HEADLESS_TEST_CASES = [
    {
        "name": "无头浏览器: 单次跳转取值",
        "category": "headless",
        "kind": "headless_browser",
        "task_text": "请通过浏览器工具找到商品详情页，告诉我商品的价格（只回答数字本身）。",
        "build_pages": _build_browser_single_hop_pages,
        "check": _check_browser_single_hop,
    },
    {
        "name": "无头浏览器: 多级跳转取值",
        "category": "headless",
        "kind": "headless_browser",
        "task_text": "请通过浏览器工具先进入电子产品分类，再找到无线耳机详情页，告诉我优惠码（只回答优惠码本身）。",
        "build_pages": _build_browser_multi_hop_pages,
        "check": _check_browser_multi_hop,
    },
]


HEADLESS_TESTS_ENABLED = False  # main.py 根据本次扫描请求的选项来开关，默认不跑(新增测试，避免默认拖慢扫描)
CORE_TESTS_ENABLED = True
CONTROL_TESTS_ENABLED = True
LANGUAGE_TESTS_ENABLED = True


def set_headless_tests_enabled(enabled: bool):
    global HEADLESS_TESTS_ENABLED
    HEADLESS_TESTS_ENABLED = bool(enabled)


def set_test_categories_enabled(core=True, control=True, language=True, headless=False):
    """指挥中心/扫描控制台的"6种测试开关"最终落到这里：每次扫描/重测前调这个函数，
    决定接下来 run_advanced_tests() 实际会跑哪些分类。"""
    global CORE_TESTS_ENABLED, CONTROL_TESTS_ENABLED, LANGUAGE_TESTS_ENABLED, HEADLESS_TESTS_ENABLED
    CORE_TESTS_ENABLED = bool(core)
    CONTROL_TESTS_ENABLED = bool(control)
    LANGUAGE_TESTS_ENABLED = bool(language)
    HEADLESS_TESTS_ENABLED = bool(headless)


CONTROL_TEST_CASES = [
    {
        "name": "Agent工具调用: 读取配置真实性",
        "category": "control",
        "kind": "agent_tool",
        "build_prompt": _build_read_config_prompt,
        "check": _check_read_config,
    },
    {
        "name": "Agent工具调用: 真实写入文件",
        "category": "control",
        "kind": "agent_tool",
        "build_prompt": _build_write_prompt,
        "check": _check_write,
    },
    {
        "name": "Agent工具调用: 多步骤列目录+定位读取",
        "category": "control",
        "kind": "agent_tool",
        "build_prompt": _build_multi_step_prompt,
        "check": _check_multi_step,
    },
]

ALL_TEST_CASES_BASE = CORE_TEST_CASES + CONTROL_TEST_CASES + LANGUAGE_TEST_CASES
ALL_TEST_CASES = ALL_TEST_CASES_BASE + HEADLESS_TEST_CASES
# 向后兼容旧名字（如果有其他地方还在引用）
ADVANCED_TEST_CASES = CORE_TEST_CASES


LOG_PERSIST_MAX_ENTRIES = 5000  # 磁盘日志文件最多保留的行数，避免长时间扫描无限增长


class ScanState:
    """扫描运行状态, 供 API 层轮询读取。

    log_file: 可选，传入一个 Path 就会把日志实时追加写入磁盘（JSONL，一行一条），
    并在进程启动时从磁盘恢复，这样即便容器被 Coolify/健康检查重启，或者用户只是刷新
    一下浏览器页面，"实时日志"面板也不会变回空的。只有 main.py 里全局唯一的那个
    `state` 会传这个参数；main.py 里那些一次性/临时的 ScanState()（例如单个测试用的
    tmp_state）不传，避免互相覆盖同一个日志文件。
    """

    def __init__(self, log_file=None):
        self.lock = threading.Lock()
        self.results_lock = threading.Lock()
        self.running = False
        self.logs = []          # [{seq, ts, text}]
        self.results = None     # 最终 JSON 结果
        self.stop_event = threading.Event()
        self._seq = 0
        self.thread = None
        self.concurrency = 3
        self.active_hosts = set()   # 正在运行中的主机, 防止同一主机被重复并发运行
        self.active_hosts_lock = threading.Lock()
        self.log_file = log_file
        if self.log_file is not None:
            self._load_persisted_logs()

    def _load_persisted_logs(self):
        try:
            if not self.log_file.exists():
                return
            entries = []
            with open(self.log_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entries.append(json.loads(line))
                    except Exception:
                        continue
            entries = entries[-LOG_PERSIST_MAX_ENTRIES:]
            self.logs = entries
            self._seq = entries[-1]["seq"] if entries else 0
        except Exception:
            # 磁盘日志损坏/读不了不应该拖垮整个后端启动，安静地当作没有历史日志即可
            pass

    def _persist_log_line(self, entry):
        if self.log_file is None:
            return
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except Exception:
            pass

    def _truncate_persisted_logs(self):
        if self.log_file is None:
            return
        try:
            if self.log_file.exists():
                self.log_file.unlink()
        except Exception:
            pass

    def log(self, text):
        with self.lock:
            self._seq += 1
            entry = {
                "seq": self._seq,
                "ts": datetime.now().strftime("%H:%M:%S"),
                "text": text,
            }
            self.logs.append(entry)
            self._persist_log_line(entry)

    def get_logs_since(self, since):
        with self.lock:
            # seq 从 1 开始严格自增、只会追加不会被删除（除非整体 reset），
            # 因此 logs[i]["seq"] == i + 1 恒成立，可以直接切片取增量，
            # 不必再对全量日志做一次线性过滤（避免长时间扫描后 O(n^2) 的轮询开销）。
            if since <= 0:
                return list(self.logs)
            if since >= self._seq:
                return []
            return self.logs[since:]

    def reset(self):
        with self.lock:
            self.logs = []
            self.results = None
            self._seq = 0
            self._truncate_persisted_logs()
        with self.active_hosts_lock:
            self.active_hosts = set()
        self.stop_event.clear()

    def request_stop(self):
        self.stop_event.set()

    def is_stopping(self):
        return self.stop_event.is_set()

    def try_acquire_host(self, host):
        """尝试独占运行某个主机, 已在运行中则返回 False (不允许重复并发)"""
        with self.active_hosts_lock:
            if host in self.active_hosts:
                return False
            self.active_hosts.add(host)
            return True

    def release_host(self, host):
        with self.active_hosts_lock:
            self.active_hosts.discard(host)


TRANSIENT_RETRY_COUNT = 1       # 网络抖动类错误(连接失败/超时)重试这么多次(不含首次请求)
TRANSIENT_RETRY_DELAY = 1.5     # 每次重试前的等待秒数


def _is_transient_error(e: Exception) -> bool:
    return isinstance(e, (requests.exceptions.ConnectionError, requests.exceptions.Timeout))


def discover_models(host):
    last_err = None
    for attempt in range(TRANSIENT_RETRY_COUNT + 1):
        try:
            resp = requests.get(f"{host}/api/tags", timeout=10)
            data = resp.json()
            models = [m["name"] for m in data.get("models", [])]
            return models, None
        except Exception as e:
            last_err = e
            if attempt < TRANSIENT_RETRY_COUNT and _is_transient_error(e):
                time.sleep(TRANSIENT_RETRY_DELAY)
                continue
            break
    return [], str(last_err)


def quick_test(host, model):
    """返回 (ok, err, elapsed_seconds)。elapsed 是本次(最后一次尝试)请求耗时，用于"快速测试"排行榜排序。"""
    last_err = None
    elapsed = None
    for attempt in range(TRANSIENT_RETRY_COUNT + 1):
        start = time.time()
        try:
            resp = requests.post(
                f"{host}/api/generate",
                json={"model": model, "prompt": "say ok", "stream": False},
                timeout=QUICK_TEST_TIMEOUT,
            )
            elapsed = round(time.time() - start, 2)
            data = resp.json()
            if "error" in data:
                return False, data["error"], elapsed  # 应用层错误(比如模型不存在)不是网络抖动，不重试
            return True, None, elapsed
        except Exception as e:
            last_err = e
            elapsed = round(time.time() - start, 2)
            if attempt < TRANSIENT_RETRY_COUNT and _is_transient_error(e):
                time.sleep(TRANSIENT_RETRY_DELAY)
                continue
            break
    return False, str(last_err), elapsed


def extract_code(text):
    patterns = [r"```python\s*(.*?)```", r"```\s*(.*?)```"]
    for pat in patterns:
        matches = re.findall(pat, text, re.DOTALL)
        if matches:
            return matches[0].strip()
    return text.strip()


def run_code(code, harness):
    """
    在受限子进程中执行模型生成的代码 + 测试 harness。
    安全说明：这里执行的是不受信任模型返回的代码，因此:
      - 使用 python3 -I (隔离模式) 忽略用户 site-packages / 环境变量注入
      - 通过 preexec_fn 设置 CPU / 内存 / 进程数 / 文件大小上限，压低失控代码
        （例如尝试常驻挖矿、fork 炸弹）的破坏半径
      - 在独立的临时目录中运行并在结束后清理，避免污染宿主文件系统
    这是尽力而为的纵深防御，不是完整沙箱；生产环境建议进一步用容器/gVisor级隔离。
    """
    full_code = code + "\n\n" + harness
    preexec = _limit_code_resources if platform.system() != "Windows" else None
    with tempfile.TemporaryDirectory(prefix="ollama-scan-") as workdir:
        try:
            result = subprocess.run(
                ["python3", "-I", "-c", full_code],
                capture_output=True,
                text=True,
                timeout=CODE_RUN_TIMEOUT,
                preexec_fn=preexec,
                cwd=workdir,
            )
            if result.returncode != 0:
                return None, (result.stdout + result.stderr).strip()[-400:]
            return result.stdout.strip(), None
        except subprocess.TimeoutExpired:
            return None, "execution timeout"
        except Exception as e:
            return None, str(e)


def query_model(host, model, prompt):
    try:
        resp = requests.post(
            f"{host}/api/generate",
            json={"model": model, "prompt": prompt, "stream": False},
            timeout=TIMEOUT,
        )
        data = resp.json()
        if "error" in data:
            return None, data["error"]
        return data.get("response", ""), None
    except Exception as e:
        return None, str(e)


def query_model_chat(host, model, messages, tools=None, timeout=TIMEOUT):
    """
    走 Ollama 的 /api/chat + tools 标准工具调用协议(和 Hermes Agent / OpenClaw 这类
    agent 框架实际驱动本地模型时用的是同一套接口), 返回单条 assistant message dict
    (可能带 tool_calls 字段)。
    """
    try:
        payload = {"model": model, "messages": messages, "stream": False}
        if tools:
            payload["tools"] = tools
        resp = requests.post(f"{host}/api/chat", json=payload, timeout=timeout)
        data = resp.json()
        if not isinstance(data, dict):
            return None, "响应格式异常(非JSON对象)"
        if "error" in data:
            return None, str(data["error"])
        return data.get("message") or {}, None
    except Exception as e:
        return None, str(e)


def run_agent_tool_task(host, model, task, state, tag="", max_turns=4):
    """
    执行一个"控制性"任务: 用标准 /api/chat + tools 协议驱动模型完成一个需要真实
    文件读写的小任务, 在独立沙箱临时目录里真实执行模型发起的工具调用, 结束后自动清理。
    用来区分"模型真的调用了工具并操作了文件" 和 "模型只是在文字里假装完成了"。
    """
    with tempfile.TemporaryDirectory(prefix="ollama-agent-") as sandbox:
        user_prompt, context = task["build_prompt"](sandbox)
        call_log = []
        executor = _make_tool_executor(sandbox, call_log)

        messages = [
            {"role": "system", "content": AGENT_SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ]

        final_text = None
        error = None
        for _ in range(max_turns):
            if state.is_stopping():
                error = "收到停止信号"
                break
            msg, err = query_model_chat(host, model, messages, tools=FS_TOOLS)
            if err:
                error = err
                break

            tool_calls = msg.get("tool_calls") or []
            content = msg.get("content", "") or ""

            assistant_msg = {"role": "assistant", "content": content}
            if tool_calls:
                assistant_msg["tool_calls"] = tool_calls
            messages.append(assistant_msg)

            if not tool_calls:
                final_text = content
                break

            for call in tool_calls:
                fn = (call or {}).get("function", {}) or {}
                name = fn.get("name")
                raw_args = fn.get("arguments", {})
                if isinstance(raw_args, str):
                    try:
                        raw_args = json.loads(raw_args) if raw_args else {}
                    except Exception:
                        raw_args = {}
                if not isinstance(raw_args, dict):
                    raw_args = {}
                result = executor(name, raw_args)
                messages.append({"role": "tool", "content": str(result)})
        else:
            error = error or "达到最大对话轮数仍未给出最终答案"

        if final_text is None and error:
            return "REQUEST_FAIL", error

        try:
            ok, detail = task["check"](call_log, final_text or "", sandbox, context)
        except Exception as e:
            ok, detail = False, f"判定过程异常: {e}"

        return ("PASS" if ok else "WRONG_OUTPUT"), detail


def run_headless_tests_only(host, model, state, tag=""):
    """只跑无头浏览器测试用例，不跑 core/control/language，用于"一键测试是否支持无头浏览器"功能。
    返回 (all_pass: bool, details: [{"name","status","detail"}])。"""
    details = []
    for case in HEADLESS_TEST_CASES:
        status, detail = run_headless_browser_task(host, model, case, state, tag=tag)
        details.append({"name": case["name"], "status": status, "detail": detail})
    all_pass = bool(details) and all(d["status"] == "PASS" for d in details)
    return all_pass, details


def process_host(host, state: ScanState, model_concurrency=4):
    """
    单个主机的完整流水线: 发现模型 -> 快速可用性测试 -> 高级测试
    在线程池的一个 worker 中运行, 日志加主机前缀以便在并发输出中区分。

    model_concurrency: 同一主机内, 同时并发测试几个模型。
    注意: 大多数 Ollama 实例同一时刻只能真正跑一个模型的推理(尤其单卡部署时会
    频繁换入换出模型), 这里的并发只是让"客户端发起请求"的动作并发, 目标主机
    自己仍然可能会排队处理。把这个值调得过高不会让单台主机的总耗时线性下降，
    反而可能因目标主机过载导致更多超时/失败, 建议保持在个位数。
    """
    import concurrent.futures

    tag = f"[{host}]"
    host_result = {"models": [], "viability": {}, "viability_timing": {}, "advanced": {}}

    if state.is_stopping():
        return host_result

    state.log(f"{tag} 开始扫描 ...")
    models, err = discover_models(host)
    if err:
        state.log(f"{tag} 发现模型失败: {err}")
        return host_result
    if not models:
        state.log(f"{tag} 未发现模型")
        return host_result

    state.log(f"{tag} 发现 {len(models)} 个模型: {', '.join(models)}")
    host_result["models"] = models

    workers = max(1, min(20, model_concurrency, len(models)))

    # ---- 阶段一: 可用性测试, 同一主机内并发跑多个模型 ----
    viable = {}
    timing = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(quick_test, host, model): model for model in models}
        for future in concurrent.futures.as_completed(futures):
            model = futures[future]
            try:
                ok, verr, elapsed = future.result()
            except Exception as e:
                ok, verr, elapsed = False, str(e), None
            viable[model] = ok
            timing[model] = elapsed
            state.log(f"{tag} {model}: {'可用' if ok else '不可用 - ' + str(verr)[:80]}")
    host_result["viability"] = viable
    host_result["viability_timing"] = timing

    if state.is_stopping():
        return host_result

    viable_models = [m for m, ok in viable.items() if ok]
    if not viable_models:
        state.log(f"{tag} 没有可用模型, 跳过高级测试")
        return host_result

    # ---- 阶段二: 高级测试, 同一主机内并发跑多个模型 ----
    adv_workers = max(1, min(20, model_concurrency, len(viable_models)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=adv_workers) as pool:
        futures = {}
        for model in viable_models:
            state.log(f"{tag} {model}: 开始高级测试")
            futures[pool.submit(run_advanced_tests, host, model, state, f"{tag}[{model}]")] = model
        for future in concurrent.futures.as_completed(futures):
            model = futures[future]
            try:
                host_result["advanced"][model] = future.result()
            except Exception as e:
                state.log(f"{tag} {model}: 高级测试过程中发生异常, 已跳过: {e}")
                host_result["advanced"][model] = []

    state.log(f"{tag} 扫描完成")
    return host_result


def _collect_test_cases(categories=None):
    """categories=None: 按当前全局开关状态选(整机扫描用)。
    categories=["core"] 这样传具体分类名列表: 忽略开关，只跑这些分类，
    给"针对单个模型点某个测试按钮单独重测"这种场景用。"""
    if categories is None:
        cases = []
        if CORE_TESTS_ENABLED:
            cases += CORE_TEST_CASES + CUSTOM_CORE_TEST_CASES
        if CONTROL_TESTS_ENABLED:
            cases += CONTROL_TEST_CASES
        if LANGUAGE_TESTS_ENABLED:
            cases += LANGUAGE_TEST_CASES + CUSTOM_LANGUAGE_TEST_CASES
        if HEADLESS_TESTS_ENABLED:
            cases += HEADLESS_TEST_CASES
        return cases

    cases = []
    if "core" in categories:
        cases += CORE_TEST_CASES + CUSTOM_CORE_TEST_CASES
    if "control" in categories:
        cases += CONTROL_TEST_CASES
    if "language" in categories:
        cases += LANGUAGE_TEST_CASES + CUSTOM_LANGUAGE_TEST_CASES
    if "headless" in categories:
        cases += HEADLESS_TEST_CASES
    return cases


def run_advanced_tests(host, model, state, tag="", categories=None):
    """
    依次跑 ALL_TEST_CASES 里的全部题目(core + control + language)。
    返回结果列表, 每项为 (name, category, status, detail, elapsed) 五元组。
    """
    results = []
    for case in _collect_test_cases(categories):
        if state.is_stopping():
            state.log(f"{tag} 已收到停止信号, 中断高级测试")
            break

        category = case.get("category", "core")
        kind = case.get("kind", "code")
        start = time.time()

        # ---- 控制性测试: 标准 tool-calling 协议 + 沙箱内真实执行 ----
        if kind == "agent_tool":
            status, detail = run_agent_tool_task(host, model, case, state, tag=tag)
            elapsed = time.time() - start
            results.append((case["name"], category, status, detail, elapsed))
            state.log(f"{tag}   [{case['name']}] {status} ({elapsed:.1f}s) {str(detail)[:100] if detail else ''}")
            continue

        # ---- 无头浏览器测试: 标准 tool-calling 协议 + 内存假站点(不联网/不需要真实浏览器) ----
        if kind == "headless_browser":
            status, detail = run_headless_browser_task(host, model, case, state, tag=tag)
            elapsed = time.time() - start
            results.append((case["name"], category, status, detail, elapsed))
            state.log(f"{tag}   [{case['name']}] {status} ({elapsed:.1f}s) {str(detail)[:100] if detail else ''}")
            continue

        # ---- 语言性 / 核心代码测试: 都先发一次 /api/generate ----
        response, err = query_model(host, model, case["prompt"])
        elapsed = time.time() - start

        if err:
            results.append((case["name"], category, "REQUEST_FAIL", err, elapsed))
            state.log(f"{tag}   [{case['name']}] REQUEST_FAIL ({elapsed:.1f}s) {err[:100]}")
            continue

        # ---- 语言性测试: 直接对原始文字用规则判定, 不执行任何代码 ----
        if kind == "language":
            checker = case["checker"]
            try:
                ok, detail = checker(response)
            except Exception as e:
                ok, detail = False, f"判定函数异常: {e}"
            status = "PASS" if ok else "WRONG_OUTPUT"
            results.append((case["name"], category, status, detail, elapsed))
            state.log(f"{tag}   [{case['name']}] {status} ({elapsed:.1f}s) {str(detail)[:100] if detail else ''}")
            continue

        # ---- 核心测试: 提取代码 -> 沙箱子进程执行 -> 校验输出 ----
        code = extract_code(response)
        output, run_err = run_code(code, case["harness"])

        # 用 output is None 判断执行失败，而不是只看 run_err 真假值：
        # run_code 在返回码非0但 stdout/stderr 恰好为空字符串时会返回 (None, "")，
        # 这个 "" 是 falsy 的，如果只判断 `if run_err:` 会被跳过，进而在下面对
        # None 执行 "ALL_PASS" in output 时抛出未捕获的 TypeError，
        # 拖垮整个扫描线程（导致"扫描过程中发生异常"、其余主机的结果全部丢失）。
        if output is None:
            detail = run_err or "代码执行失败且无输出"
            results.append((case["name"], category, "CODE_ERROR", detail, elapsed))
            state.log(f"{tag}   [{case['name']}] CODE_ERROR ({elapsed:.1f}s) {detail[:100]}")
            continue

        if output == case.get("expected") or "ALL_PASS" in output:
            results.append((case["name"], category, "PASS", None, elapsed))
            state.log(f"{tag}   [{case['name']}] PASS ({elapsed:.1f}s)")
        else:
            results.append((case["name"], category, "WRONG_OUTPUT", output, elapsed))
            state.log(f"{tag}   [{case['name']}] WRONG_OUTPUT ({elapsed:.1f}s) {str(output)[:100]}")

    return results


def run_scan(hosts, state: ScanState, concurrency=3, model_concurrency=4):
    """
    主扫描流程, 在后台线程中执行。
    使用线程池并发处理多个主机, 并发数由 concurrency (1-100) 控制。
    每个主机内部测试多个模型时, 并发数由 model_concurrency 控制。
    同一个主机不会被重复并发运行 (try_acquire_host 保证独占)。
    """
    import concurrent.futures

    state.reset()
    state.running = True
    state.concurrency = concurrency
    try:
        state.log("=" * 60)
        state.log(f"开始扫描 {len(hosts)} 个主机, 主机并发数: {concurrency}, 单主机内模型并发数: {model_concurrency}")
        state.log("=" * 60)

        all_results = {}  # host -> host_result

        def worker(host):
            if not state.try_acquire_host(host):
                state.log(f"[{host}] 已在运行中, 跳过重复任务")
                return host, None
            try:
                try:
                    return host, process_host(host, state, model_concurrency=model_concurrency)
                except Exception as e:
                    # 单个主机处理过程中出现任何意外异常都不应该拖垮整个扫描，
                    # 只记录该主机失败，其余主机的结果继续正常保留。
                    state.log(f"[{host}] 处理过程中发生异常, 已跳过: {e}")
                    return host, {"models": [], "viability": {}, "advanced": {}, "error": str(e)}
            finally:
                state.release_host(host)

        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(100, concurrency))) as pool:
            futures = {pool.submit(worker, host): host for host in hosts}
            for future in concurrent.futures.as_completed(futures):
                host, result = future.result()
                if result is not None:
                    with state.results_lock:
                        all_results[host] = result

        state.log("")
        state.log("=" * 60)
        state.log("最终结果")
        state.log("=" * 60)

        discovered = {h: r["models"] for h, r in all_results.items() if r.get("models")}
        viability = {}
        viability_timing = {}
        advanced = {}
        for h, r in all_results.items():
            for m, ok in r.get("viability", {}).items():
                viability[f"{h}|{m}"] = ok
            for m, t in r.get("viability_timing", {}).items():
                viability_timing[f"{h}|{m}"] = t
            for m, tests in r.get("advanced", {}).items():
                advanced[f"{h}|{m}"] = tests

        # 每台主机的整体状态：discover 都没成功 -> unreachable；发现了模型但全部连不上 -> all_down；否则 ok
        host_status = {}
        for h in hosts:
            models = discovered.get(h)
            if not models:
                host_status[h] = "unreachable"
                continue
            vals = [viability.get(f"{h}|{m}") for m in models]
            host_status[h] = "all_down" if vals and all(v is False for v in vals) else "ok"

        # 按三个维度(core/control/language)分别统计通过情况用于摘要日志
        category_labels = {"core": "核心测试", "control": "控制性(Agent工具调用)", "language": "语言性"}
        category_summary = {cat: {"passed": [], "failed": []} for cat in category_labels}
        for key, tests in advanced.items():
            host, model = key.split("|", 1)
            model_key = f"{model} @ {host}"
            by_cat = defaultdict(list)
            for name, category, status, detail, elapsed in tests:
                by_cat[category].append(status)
            for cat, statuses in by_cat.items():
                if cat not in category_summary:
                    continue
                if statuses and all(s == "PASS" for s in statuses):
                    category_summary[cat]["passed"].append(model_key)
                else:
                    category_summary[cat]["failed"].append(model_key)

        any_summary = False
        for cat, label in category_labels.items():
            passed = category_summary[cat]["passed"]
            failed = category_summary[cat]["failed"]
            if not passed and not failed:
                continue
            any_summary = True
            state.log(f"{label} — 全部通过 {len(passed)} 个, 存在失败项 {len(failed)} 个")
            for m in passed:
                state.log(f"  ✔ [{label}] {m}")
            for m in failed:
                state.log(f"  ✘ [{label}] {m}")
        if not any_summary:
            state.log("没有模型进入高级测试阶段")

        state.results = {
            "discovered": discovered,
            "viability": viability,
            "viability_timing": viability_timing,
            "host_status": host_status,
            "advanced": {
                key: [
                    {
                        "test": name,
                        "category": category,
                        "status": status,
                        "detail": (str(detail)[:300] if detail else None),
                        "elapsed": elapsed,
                    }
                    for name, category, status, detail, elapsed in tests
                ]
                for key, tests in advanced.items()
            },
            "generated_at": datetime.now().isoformat(),
        }
        state.log("\n扫描完成" if not state.is_stopping() else "\n扫描已停止")
    except Exception as e:
        state.log(f"扫描过程中发生异常: {e}")
    finally:
        state.running = False


def start_scan_thread(hosts, state: ScanState, concurrency=3, model_concurrency=4):
    if state.running:
        return False
    t = threading.Thread(target=run_scan, args=(hosts, state, concurrency, model_concurrency), daemon=True)
    state.thread = t
    t.start()
    return True
