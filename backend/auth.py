"""
认证与防爆破模块
- 密码使用 PBKDF2-HMAC-SHA256 加盐哈希存储，从不明文落盘
- 登录失败按 IP 计数，达到阈值后触发指数退避锁定（3 次内不锁，之后 2^(fails-3) 分钟，上限 60 分钟）
- 会话为服务端随机 token，通过 HttpOnly / SameSite=Strict Cookie 下发，内存持有 + 定期落盘防止重启后全部失效
"""
import base64
import hashlib
import hmac
import json
import os
import secrets
import struct
import time
from pathlib import Path

PBKDF2_ITERATIONS = 200_000
SESSION_TTL_SECONDS = 12 * 3600  # 会话有效期 12 小时
LOCK_FREE_ATTEMPTS = 3           # 前 3 次失败不锁定
LOCK_MAX_MINUTES = 60            # 单次锁定时长上限
TOTP_STEP_SECONDS = 30
TOTP_DIGITS = 6
TOTP_WINDOW = 1  # 允许前后各 1 个时间步的时钟误差


class AuthManager:
    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self.auth_file = data_dir / "auth.json"
        self.attempts_file = data_dir / "login_attempts.json"
        self.sessions_file = data_dir / "sessions.json"

        self.attempts = self._load_json(self.attempts_file, {})
        self.sessions = self._load_json(self.sessions_file, {})
        self._prune_sessions()
        self._ensure_password()

    # ---------------- 密码管理 ----------------

    def _ensure_password(self):
        env_pw = os.environ.get("ADMIN_PASSWORD")
        if self.auth_file.exists():
            data = self._load_json(self.auth_file, {})
            if env_pw and data.get("hash") and not self._verify_hash(env_pw, data.get("salt", ""), data.get("hash", "")):
                # 环境变量密码与已存哈希不一致时，以环境变量为准（便于运维通过改环境变量重置密码）
                self._set_password(env_pw)
            return
        pw = env_pw or secrets.token_urlsafe(9)
        self._set_password(pw)
        if not env_pw:
            print("=" * 60)
            print(f"[ollama-scanner] 未设置 ADMIN_PASSWORD 环境变量，已自动生成初始密码：{pw}")
            print("[ollama-scanner] 请立即记录此密码，或通过环境变量 ADMIN_PASSWORD 固定密码后重新部署。")
            print("=" * 60)

    def _set_password(self, pw: str):
        salt = secrets.token_hex(16)
        h = self._hash(pw, salt)
        self._save_json(self.auth_file, {"salt": salt, "hash": h, "updated_at": time.time()})

    def _hash(self, pw: str, salt: str) -> str:
        return hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt.encode("utf-8"), PBKDF2_ITERATIONS).hex()

    def _verify_hash(self, pw: str, salt: str, expected: str) -> bool:
        if not salt or not expected:
            return False
        return hmac.compare_digest(self._hash(pw, salt), expected)

    def verify_password(self, pw: str) -> bool:
        data = self._load_json(self.auth_file, {})
        return self._verify_hash(pw, data.get("salt", ""), data.get("hash", ""))

    # ---------------- TOTP 两步验证 ----------------
    # 密钥以 Base32 明文存放在 auth.json 里(和 ADMIN_PASSWORD 同一信任模型：
    # 容器本身已经通过密码鉴权 + HTTPS 反代保护)。校验通过标准 RFC 6238 算法，
    # 允许前后各 1 个时间步(±30s)的时钟误差，并记录最近一次成功使用的时间步防止同一验证码被重放。

    def is_totp_enabled(self) -> bool:
        data = self._load_json(self.auth_file, {})
        return bool(data.get("totp_secret") and data.get("totp_enabled"))

    def generate_totp_secret(self) -> str:
        """生成一个新的 Base32 密钥，暂存但不启用，等待用户输入一次验证码确认后再 enable_totp。"""
        secret = base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")
        data = self._load_json(self.auth_file, {})
        data["totp_pending_secret"] = secret
        data["totp_enabled"] = data.get("totp_enabled", False)
        self._save_json(self.auth_file, data)
        return secret

    def enable_totp(self, code: str) -> bool:
        """用刚生成的 pending secret 校验一次验证码，通过后才正式启用。"""
        data = self._load_json(self.auth_file, {})
        pending = data.get("totp_pending_secret")
        if not pending or not self._totp_verify_code(pending, code):
            return False
        data["totp_secret"] = pending
        data["totp_enabled"] = True
        data.pop("totp_pending_secret", None)
        data.pop("totp_last_step", None)
        self._save_json(self.auth_file, data)
        return True

    def disable_totp(self):
        data = self._load_json(self.auth_file, {})
        data.pop("totp_secret", None)
        data.pop("totp_pending_secret", None)
        data.pop("totp_last_step", None)
        data["totp_enabled"] = False
        self._save_json(self.auth_file, data)

    def verify_totp(self, code: str) -> bool:
        data = self._load_json(self.auth_file, {})
        if not data.get("totp_enabled") or not data.get("totp_secret"):
            return False
        secret = data["totp_secret"]
        ok, step = self._totp_verify_code(secret, code, return_step=True)
        if not ok:
            return False
        if step is not None and step == data.get("totp_last_step"):
            return False  # 同一个验证码在同一时间步内不能被重复使用(防重放)
        data["totp_last_step"] = step
        self._save_json(self.auth_file, data)
        return True

    @staticmethod
    def _totp_code_for_step(secret: str, step: int) -> str:
        key = base64.b32decode(secret.upper() + "=" * ((8 - len(secret) % 8) % 8))
        msg = struct.pack(">Q", step)
        h = hmac.new(key, msg, hashlib.sha1).digest()
        offset = h[-1] & 0x0F
        code_int = (struct.unpack(">I", h[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** TOTP_DIGITS)
        return str(code_int).zfill(TOTP_DIGITS)

    def _totp_verify_code(self, secret: str, code: str, return_step: bool = False):
        code = (code or "").strip()
        if not code.isdigit() or len(code) != TOTP_DIGITS:
            return (False, None) if return_step else False
        now_step = int(time.time() // TOTP_STEP_SECONDS)
        for delta in range(-TOTP_WINDOW, TOTP_WINDOW + 1):
            step = now_step + delta
            if hmac.compare_digest(self._totp_code_for_step(secret, step), code):
                return (True, step) if return_step else True
        return (False, None) if return_step else False

    # ---------------- 登录失败锁定（防爆破） ----------------

    def is_locked(self, ip: str) -> float:
        """返回剩余锁定秒数，未锁定返回 0"""
        rec = self.attempts.get(ip)
        if not rec:
            return 0.0
        remain = rec.get("locked_until", 0) - time.time()
        return max(0.0, remain)

    def register_failure(self, ip: str) -> dict:
        rec = self.attempts.setdefault(ip, {"fails": 0, "locked_until": 0, "first_fail": time.time()})
        rec["fails"] += 1
        rec["last_fail"] = time.time()
        if rec["fails"] > LOCK_FREE_ATTEMPTS:
            backoff_minutes = min(LOCK_MAX_MINUTES, 2 ** (rec["fails"] - LOCK_FREE_ATTEMPTS - 1))
            rec["locked_until"] = time.time() + backoff_minutes * 60
        self._save_json(self.attempts_file, self.attempts)
        return rec

    def register_success(self, ip: str):
        if ip in self.attempts:
            del self.attempts[ip]
            self._save_json(self.attempts_file, self.attempts)

    # ---------------- 会话 ----------------

    def create_session(self) -> str:
        token = secrets.token_urlsafe(32)
        self.sessions[token] = time.time() + SESSION_TTL_SECONDS
        self._save_json(self.sessions_file, self.sessions)
        return token

    def validate_session(self, token: str) -> bool:
        if not token:
            return False
        exp = self.sessions.get(token)
        if not exp:
            return False
        if exp < time.time():
            del self.sessions[token]
            self._save_json(self.sessions_file, self.sessions)
            return False
        return True

    def destroy_session(self, token: str):
        if token and token in self.sessions:
            del self.sessions[token]
            self._save_json(self.sessions_file, self.sessions)

    def _prune_sessions(self):
        now = time.time()
        before = len(self.sessions)
        self.sessions = {t: exp for t, exp in self.sessions.items() if exp > now}
        if len(self.sessions) != before:
            self._save_json(self.sessions_file, self.sessions)

    # ---------------- 工具 ----------------

    @staticmethod
    def _load_json(path: Path, default):
        if not path.exists():
            return default
        try:
            return json.loads(path.read_text())
        except Exception:
            return default

    @staticmethod
    def _save_json(path: Path, data):
        try:
            tmp = path.with_name(f".{path.name}.tmp.{os.getpid()}.{secrets.token_hex(4)}")
            tmp.write_text(json.dumps(data, ensure_ascii=False))
            os.replace(tmp, path)
        except Exception:
            pass
