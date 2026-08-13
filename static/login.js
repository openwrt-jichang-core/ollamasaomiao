if (window.localStorage.getItem('ollama-scanner-theme') === 'light') {
  document.documentElement.setAttribute('data-theme', 'light');
}

const loginForm = document.getElementById('loginForm');
const loginPassword = document.getElementById('loginPassword');
const loginTotp = document.getElementById('loginTotp');
const loginSubmit = document.getElementById('loginSubmit');
const loginError = document.getElementById('loginError');

let lockdownTimer = null;
let totpRequired = false;

function setError(msg) {
  loginError.textContent = msg || '';
}

function startLockCountdown(seconds) {
  clearInterval(lockdownTimer);
  let remain = Math.ceil(seconds);
  loginSubmit.disabled = true;
  const tick = () => {
    if (remain <= 0) {
      clearInterval(lockdownTimer);
      loginSubmit.disabled = false;
      setError('');
      return;
    }
    setError(`尝试次数过多，请在 ${remain} 秒后再试`);
    remain -= 1;
  };
  tick();
  lockdownTimer = setInterval(tick, 1000);
}

function detailMessage(detail) {
  if (!detail) return '';
  if (typeof detail === 'string') return detail;
  return detail.message || '';
}

loginForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const password = loginPassword.value;
  if (!password) {
    setError('请输入密码');
    return;
  }
  loginSubmit.disabled = true;
  setError('');
  try {
    const res = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password, totp_code: totpRequired ? loginTotp.value.trim() : undefined }),
    });
    if (res.ok) {
      window.location.href = '/';
      return;
    }
    const err = await res.json().catch(() => ({}));
    if (res.status === 429) {
      const match = /(\d+)\s*秒/.exec(detailMessage(err.detail));
      if (match) {
        startLockCountdown(parseInt(match[1], 10));
      } else {
        setError(detailMessage(err.detail) || '请求过于频繁，请稍后再试');
        loginSubmit.disabled = false;
      }
    } else if (err.detail && typeof err.detail === 'object' && err.detail.code === 'totp_required') {
      totpRequired = true;
      loginTotp.style.display = '';
      loginTotp.focus();
      setError(err.detail.message || '请输入两步验证码');
      loginSubmit.disabled = false;
      return; // 保留已输入的密码，不清空
    } else {
      setError(detailMessage(err.detail) || '密码错误');
      loginSubmit.disabled = false;
    }
  } catch (err) {
    setError('网络错误，请重试');
    loginSubmit.disabled = false;
  }
  loginPassword.value = '';
  loginPassword.focus();
});
