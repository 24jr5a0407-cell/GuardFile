// TrustVault Authentication & Session Management Module

let currentUser = null;
let pending2FA = null;

function getToken() {
  return localStorage.getItem('trustvault_token');
}

function setToken(token) {
  localStorage.setItem('trustvault_token', token);
}

function clearSession() {
  localStorage.removeItem('trustvault_token');
  currentUser = null;
  pending2FA = null;
  renderAuthHeader();
  loadDocuments();
}

/**
 * Initializes and checks session on app load.
 */
async function initAuth() {
  const token = getToken();
  if (!token) {
    // If no session, auto-login as Alice (Owner) for instant demo experience
    await quickLogin('alice@trustvault.local', 'OwnerPassword123!');
    return;
  }

  try {
    const res = await fetch('/api/auth/me', {
      headers: { Authorization: `Bearer ${token}` },
    });

    if (res.ok) {
      const data = await res.json();
      currentUser = data.user;
      renderAuthHeader();
    } else {
      clearSession();
    }
  } catch (err) {
    console.error('Session check failed:', err);
    clearSession();
  }
}

/**
 * Quick Login function for the Judge Switcher in the top bar.
 */
async function quickLogin(email, password) {
  try {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password, require2fa: false }),
    });

    const data = await res.json();

    if (!res.ok) {
      showToast('Login Failed', data.error || 'Invalid credentials', 'error');
      return;
    }

    setToken(data.token);
    currentUser = data.user;
    renderAuthHeader();
    showToast('Role Switched', `Active Session: ${currentUser.name} (${currentUser.role.toUpperCase()})`, 'success');

    // Reload documents and audit trail for the new role
    if (typeof loadDocuments === 'function') loadDocuments();
    if (typeof loadAuditLogs === 'function') loadAuditLogs();
    if (typeof updateStats === 'function') updateStats();
  } catch (err) {
    console.error('Quick login error:', err);
    showToast('Login Error', err.message, 'error');
  }
}

/**
 * Renders user profile pill and active role in the top navigation bar.
 */
function renderAuthHeader() {
  const container = document.getElementById('auth-header-container');
  if (!container) return;

  // Highlight active role button in the switcher
  ['admin', 'alice', 'bob', 'charlie'].forEach(r => {
    const btn = document.getElementById(`role-btn-${r}`);
    if (btn) btn.classList.remove('bg-white', 'shadow-xs', 'text-blue-700', 'font-bold');
  });

  if (!currentUser) {
    container.innerHTML = `
      <button onclick="openLoginModal()" class="px-4 py-2 text-xs font-bold text-white bg-blue-600 rounded-xl hover:bg-blue-700 shadow-xs transition">
        Sign In
      </button>
    `;
    return;
  }

  // Highlight matching switcher button
  if (currentUser.email.startsWith('admin')) {
    document.getElementById('role-btn-admin')?.classList.add('bg-white', 'shadow-xs', 'text-blue-700', 'font-bold');
  } else if (currentUser.email.startsWith('alice')) {
    document.getElementById('role-btn-alice')?.classList.add('bg-white', 'shadow-xs', 'text-blue-700', 'font-bold');
  } else if (currentUser.email.startsWith('bob')) {
    document.getElementById('role-btn-bob')?.classList.add('bg-white', 'shadow-xs', 'text-blue-700', 'font-bold');
  } else if (currentUser.email.startsWith('charlie')) {
    document.getElementById('role-btn-charlie')?.classList.add('bg-white', 'shadow-xs', 'text-blue-700', 'font-bold');
  }

  const roleColors = {
    admin: 'bg-purple-100 text-purple-800 border-purple-200',
    owner: 'bg-blue-100 text-blue-800 border-blue-200',
    viewer: 'bg-emerald-100 text-emerald-800 border-emerald-200',
  };

  container.innerHTML = `
    <div class="flex items-center gap-3">
      <div class="flex items-center gap-2.5 bg-slate-100 py-1.5 px-3 rounded-xl border border-slate-200">
        <div class="w-7 h-7 rounded-lg bg-slate-900 text-white flex items-center justify-center font-bold text-xs uppercase">
          ${currentUser.name.charAt(0)}
        </div>
        <div class="text-left hidden sm:block">
          <p class="text-xs font-bold text-slate-900 leading-tight">${currentUser.name}</p>
          <p class="text-[10px] text-slate-500">${currentUser.email}</p>
        </div>
        <span class="text-[10px] font-bold uppercase px-2 py-0.5 rounded-full border ${roleColors[currentUser.role] || 'bg-slate-200'}">
          ${currentUser.role}
        </span>
      </div>

      <button onclick="clearSession()" class="p-2 text-slate-400 hover:text-rose-600 rounded-xl hover:bg-rose-50 transition" title="Log out">
        <i data-lucide="log-out" class="w-4 h-4"></i>
      </button>
    </div>
  `;

  // Hide upload button if Viewer
  const uploadBtn = document.getElementById('btn-open-upload');
  if (uploadBtn) {
    uploadBtn.style.display = (currentUser.role === 'viewer') ? 'none' : 'flex';
  }

  lucide.createIcons();
}

function openLoginModal() {
  document.getElementById('modal-auth')?.classList.remove('hidden');
  document.getElementById('login-form')?.classList.remove('hidden');
  document.getElementById('otp-form')?.classList.add('hidden');
}

function closeLoginModal() {
  document.getElementById('modal-auth')?.classList.add('hidden');
}

async function handleLoginSubmit(e) {
  e.preventDefault();
  const email = document.getElementById('login-email').value;
  const password = document.getElementById('login-password').value;
  const require2fa = document.getElementById('login-require-2fa').checked;
  const errorEl = document.getElementById('login-error');

  errorEl.classList.add('hidden');

  try {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password, require2fa }),
    });

    const data = await res.json();

    if (!res.ok) {
      errorEl.textContent = data.error || 'Login failed.';
      errorEl.classList.remove('hidden');
      return;
    }

    if (data.require2FA) {
      // Transition to OTP verification step
      pending2FA = data;
      document.getElementById('login-form').classList.add('hidden');
      document.getElementById('otp-form').classList.remove('hidden');
      document.getElementById('otp-status-text').textContent = data.message;
      if (data.devOtp) {
        document.getElementById('otp-dev-hint').textContent = `Demo Code: ${data.devOtp}`;
        document.getElementById('otp-code-input').value = data.devOtp;
      }
      return;
    }

    setToken(data.token);
    currentUser = data.user;
    renderAuthHeader();
    closeLoginModal();
    showToast('Logged In', `Welcome back, ${currentUser.name}!`, 'success');
    loadDocuments();
    updateStats();
  } catch (err) {
    errorEl.textContent = err.message;
    errorEl.classList.remove('hidden');
  }
}

async function handleOtpSubmit(e) {
  e.preventDefault();
  const otpCode = document.getElementById('otp-code-input').value;
  const errorEl = document.getElementById('otp-error');
  errorEl.classList.add('hidden');

  try {
    const res = await fetch('/api/auth/verify-otp', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ userId: pending2FA.userId, otpCode }),
    });

    const data = await res.json();

    if (!res.ok) {
      errorEl.textContent = data.error || 'Verification failed.';
      errorEl.classList.remove('hidden');
      return;
    }

    setToken(data.token);
    currentUser = data.user;
    renderAuthHeader();
    closeLoginModal();
    showToast('2FA Verified', `Welcome back, ${currentUser.name}!`, 'success');
    loadDocuments();
    updateStats();
  } catch (err) {
    errorEl.textContent = err.message;
    errorEl.classList.remove('hidden');
  }
}
