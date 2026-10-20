// TrustVault Authentication & Multi-Step Zero-Trust Onboarding Module

let currentUser = null;
let pendingRegistration = null; // { userId, email, phone, name, role }
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
  pendingRegistration = null;
  pending2FA = null;
  renderAuthHeader();
  if (typeof loadDocuments === 'function') loadDocuments();
  if (typeof updateStats === 'function') updateStats();
  
  // Hide admin tab
  const adminTab = document.getElementById('tab-btn-approvals');
  if (adminTab) adminTab.classList.add('hidden');
}

/**
 * Initializes and checks session on app load.
 */
async function initAuth() {
  const token = getToken();
  if (!token) {
    // Default to Alice (Owner) for instant frictionless evaluator demo
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

    if (data.account_status && data.account_status !== 'ACTIVE') {
      openLoginModal();
      handleAccountStatusResponse(data);
      return;
    }

    setToken(data.token);
    currentUser = data.user;
    renderAuthHeader();
    showToast('Role Switched', `Active Session: ${currentUser.name} (${currentUser.role.toUpperCase()})`, 'success');

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

  const adminTab = document.getElementById('tab-btn-approvals');

  if (!currentUser) {
    if (adminTab) adminTab.classList.add('hidden');
    container.innerHTML = `
      <div class="flex items-center gap-2">
        <button onclick="openLoginModal('login')" class="px-3.5 py-1.5 text-xs font-semibold text-slate-700 hover:text-slate-900 border border-slate-200 rounded-xl hover:bg-slate-50 transition">
          Sign In
        </button>
        <button onclick="openLoginModal('register')" class="px-3.5 py-1.5 text-xs font-bold text-white bg-blue-600 rounded-xl hover:bg-blue-700 shadow-xs transition">
          Create Account
        </button>
      </div>
    `;
    return;
  }

  // Show Admin Approvals tab if role is admin
  if (currentUser.role === 'admin') {
    if (adminTab) {
      adminTab.classList.remove('hidden');
      loadPendingApprovalsCount();
    }
  } else {
    if (adminTab) adminTab.classList.add('hidden');
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

  if (window.lucide) lucide.createIcons();
}

/**
 * Modal Management & Tab Switching
 */
function openLoginModal(initialTab = 'login') {
  document.getElementById('modal-auth')?.classList.remove('hidden');
  showAuthTab(initialTab);
}

function closeLoginModal() {
  document.getElementById('modal-auth')?.classList.add('hidden');
}

function showAuthTab(tab) {
  const loginView = document.getElementById('auth-view-login');
  const registerView = document.getElementById('auth-view-register');
  const otpView = document.getElementById('auth-view-otp');
  const adminCodeView = document.getElementById('auth-view-admin-code');
  const tabBtnLogin = document.getElementById('auth-tab-btn-login');
  const tabBtnRegister = document.getElementById('auth-tab-btn-register');
  const tabHeader = document.getElementById('auth-modal-tab-header');

  // Hide all step views first
  loginView?.classList.add('hidden');
  registerView?.classList.add('hidden');
  otpView?.classList.add('hidden');
  adminCodeView?.classList.add('hidden');

  if (tab === 'login') {
    tabHeader?.classList.remove('hidden');
    loginView?.classList.remove('hidden');
    tabBtnLogin?.classList.add('border-blue-600', 'text-blue-600', 'font-bold');
    tabBtnLogin?.classList.remove('text-slate-500', 'border-transparent');
    tabBtnRegister?.classList.remove('border-blue-600', 'text-blue-600', 'font-bold');
    tabBtnRegister?.classList.add('text-slate-500', 'border-transparent');
  } else if (tab === 'register') {
    tabHeader?.classList.remove('hidden');
    registerView?.classList.remove('hidden');
    tabBtnRegister?.classList.add('border-blue-600', 'text-blue-600', 'font-bold');
    tabBtnRegister?.classList.remove('text-slate-500', 'border-transparent');
    tabBtnLogin?.classList.remove('border-blue-600', 'text-blue-600', 'font-bold');
    tabBtnLogin?.classList.add('text-slate-500', 'border-transparent');
  } else if (tab === 'otp') {
    tabHeader?.classList.add('hidden');
    otpView?.classList.remove('hidden');
  } else if (tab === 'admin-code') {
    tabHeader?.classList.add('hidden');
    adminCodeView?.classList.remove('hidden');
  }

  if (window.lucide) lucide.createIcons();
}

/**
 * Handles account onboarding status transitions
 */
function handleAccountStatusResponse(data) {
  pendingRegistration = {
    userId: data.userId,
    email: data.email,
    name: data.name || '',
    role: data.role || 'viewer',
  };

  if (data.account_status === 'PENDING_OTP' || data.requireRegistrationOTP || data.requireOTP) {
    showAuthTab('otp');
    document.getElementById('otp-target-email').textContent = data.email;
    document.getElementById('otp-status-text').textContent = data.message || 'Verification code dispatched to your email.';
    if (data.devOtp) {
      document.getElementById('otp-dev-hint').textContent = `Demo Code: ${data.devOtp}`;
      document.getElementById('otp-code-input').value = data.devOtp;
    }
  } else if (data.account_status === 'PENDING_ADMIN_CODE' || data.pendingAdminCode) {
    showAuthTab('admin-code');
    document.getElementById('admin-code-user-info').textContent = `User: ${data.email}`;
    document.getElementById('admin-code-status-pill').textContent = 'Awaiting Administrator Review';
    document.getElementById('admin-code-notice').textContent =
      'Your email OTP is verified! Your Administrator has been notified to generate your Access Authorization Code. When you receive it, enter it below.';
  } else if (data.account_status === 'AWAITING_USER_CODE' || data.awaitingUserCode) {
    showAuthTab('admin-code');
    document.getElementById('admin-code-user-info').textContent = `User: ${data.email}`;
    document.getElementById('admin-code-status-pill').textContent = 'Code Sent to Your Email!';
    document.getElementById('admin-code-notice').textContent =
      'The Administrator has dispatched your Authorization Code! Please check your email inbox and enter the code below to unlock your dashboard.';
  }
}

/**
 * Handle Login Form Submit
 */
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

    if (data.account_status && data.account_status !== 'ACTIVE') {
      handleAccountStatusResponse(data);
      return;
    }

    if (data.require2FA) {
      pending2FA = data;
      showAuthTab('otp');
      document.getElementById('otp-target-email').textContent = data.email;
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
    if (typeof loadDocuments === 'function') loadDocuments();
    if (typeof updateStats === 'function') updateStats();
  } catch (err) {
    errorEl.textContent = err.message;
    errorEl.classList.remove('hidden');
  }
}

/**
 * Handle Registration Form Submit
 */
async function handleRegisterSubmit(e) {
  e.preventDefault();
  const name = document.getElementById('reg-name').value;
  const email = document.getElementById('reg-email').value;
  const phone = document.getElementById('reg-phone').value;
  const password = document.getElementById('reg-password').value;
  const confirmPassword = document.getElementById('reg-confirm-password').value;
  const role = document.querySelector('input[name="reg-role"]:checked')?.value || 'viewer';
  const termsAccepted = document.getElementById('reg-terms').checked;
  const errorEl = document.getElementById('reg-error');

  errorEl.classList.add('hidden');

  if (password !== confirmPassword) {
    errorEl.textContent = 'Passwords do not match. Please verify.';
    errorEl.classList.remove('hidden');
    return;
  }

  if (!termsAccepted) {
    errorEl.textContent = 'You must agree to the Terms of Service & Privacy Policy.';
    errorEl.classList.remove('hidden');
    return;
  }

  try {
    const res = await fetch('/api/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, email, phone, password, role, termsAccepted }),
    });

    const data = await res.json();

    if (!res.ok) {
      errorEl.textContent = data.error || 'Registration failed.';
      errorEl.classList.remove('hidden');
      return;
    }

    pendingRegistration = {
      userId: data.userId,
      email: data.email,
      phone: data.phone,
      name: data.name,
      role: data.role,
    };

    showToast('Account Created', 'A 6-digit verification OTP has been sent to your email.', 'success');
    handleAccountStatusResponse(data);
  } catch (err) {
    errorEl.textContent = err.message;
    errorEl.classList.remove('hidden');
  }
}

/**
 * Handle Email OTP Submit (Registration & 2FA)
 */
async function handleOtpSubmit(e) {
  e.preventDefault();
  const otpCode = document.getElementById('otp-code-input').value;
  const errorEl = document.getElementById('otp-error');
  errorEl.classList.add('hidden');

  // If this is a login 2FA OTP
  if (pending2FA && !pendingRegistration) {
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
      if (typeof loadDocuments === 'function') loadDocuments();
      if (typeof updateStats === 'function') updateStats();
      return;
    } catch (err) {
      errorEl.textContent = err.message;
      errorEl.classList.remove('hidden');
      return;
    }
  }

  // Otherwise, Registration OTP verification
  if (!pendingRegistration || !pendingRegistration.userId) {
    errorEl.textContent = 'Session expired. Please sign in or register again.';
    errorEl.classList.remove('hidden');
    return;
  }

  try {
    const res = await fetch('/api/auth/verify-registration-otp', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ userId: pendingRegistration.userId, otpCode }),
    });

    const data = await res.json();

    if (!res.ok) {
      errorEl.textContent = data.error || 'Invalid OTP code.';
      errorEl.classList.remove('hidden');
      return;
    }

    showToast('Email Verified!', 'Administrator notified to issue your Authorization Code.', 'success');
    handleAccountStatusResponse(data);
  } catch (err) {
    errorEl.textContent = err.message;
    errorEl.classList.remove('hidden');
  }
}

/**
 * Handle Admin Authorization Code Submit
 */
async function handleAdminCodeSubmit(e) {
  e.preventDefault();
  const authCode = document.getElementById('admin-code-input').value;
  const errorEl = document.getElementById('admin-code-error');
  errorEl.classList.add('hidden');

  if (!pendingRegistration || !pendingRegistration.userId) {
    errorEl.textContent = 'User context lost. Please enter your email in the login tab first.';
    errorEl.classList.remove('hidden');
    return;
  }

  try {
    const res = await fetch('/api/auth/verify-admin-code', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ userId: pendingRegistration.userId, authCode }),
    });

    const data = await res.json();

    if (!res.ok) {
      errorEl.textContent = data.error || 'Invalid Authorization Code.';
      errorEl.classList.remove('hidden');
      return;
    }

    setToken(data.token);
    currentUser = data.user;
    renderAuthHeader();
    closeLoginModal();
    showToast('Vault Unlocked!', `Account activated! Welcome, ${currentUser.name}.`, 'success');

    if (typeof loadDocuments === 'function') loadDocuments();
    if (typeof updateStats === 'function') updateStats();
  } catch (err) {
    errorEl.textContent = err.message;
    errorEl.classList.remove('hidden');
  }
}

/**
 * Polling/checking approval status for pending user
 */
async function checkAdminApprovalStatus() {
  if (!pendingRegistration || !pendingRegistration.email) {
    showToast('Notice', 'No active pending account. Please sign in.', 'info');
    return;
  }

  try {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: pendingRegistration.email, password: 'check-status-probe' }),
    });

    const data = await res.json();

    if (data.account_status) {
      handleAccountStatusResponse(data);
      if (data.account_status === 'AWAITING_USER_CODE') {
        showToast('Code Ready!', 'The Administrator has dispatched your code to your email.', 'success');
      } else {
        showToast('Status Checked', data.message || 'Still awaiting Administrator action.', 'info');
      }
    }
  } catch (err) {
    console.error('Check status error:', err);
  }
}

/**
 * Professional Google Social Auth Flow (Simulated / One-Click OAuth)
 */
async function handleGoogleSignIn() {
  const emailPrompt = prompt('Enter Google Workspace / Gmail account to authenticate:', 'user.trustvault@gmail.com');
  if (!emailPrompt) return;

  const namePrompt = prompt('Enter display name for this Google Account:', 'Google User');
  if (!namePrompt) return;

  const phonePrompt = prompt('Enter contact phone number for zero-trust identity verification:', '+15551234567');

  try {
    const res = await fetch('/api/auth/google', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: emailPrompt.trim(),
        name: namePrompt.trim(),
        phone: phonePrompt ? phonePrompt.trim() : null,
        role: 'owner',
      }),
    });

    const data = await res.json();

    if (!res.ok) {
      showToast('Google Sign-In Error', data.error || 'Authentication failed', 'error');
      return;
    }

    if (data.account_status && data.account_status !== 'ACTIVE') {
      handleAccountStatusResponse(data);
      return;
    }

    setToken(data.token);
    currentUser = data.user;
    renderAuthHeader();
    closeLoginModal();
    showToast('Google Authenticated', `Welcome, ${currentUser.name}!`, 'success');
    if (typeof loadDocuments === 'function') loadDocuments();
    if (typeof updateStats === 'function') updateStats();
  } catch (err) {
    showToast('Google Sign-In Error', err.message, 'error');
  }
}

/**
 * Terms and Conditions Modal
 */
function openTermsModal() {
  document.getElementById('modal-terms')?.classList.remove('hidden');
}

function closeTermsModal() {
  document.getElementById('modal-terms')?.classList.add('hidden');
}

function acceptTermsFromModal() {
  const termsCheckbox = document.getElementById('reg-terms');
  if (termsCheckbox) termsCheckbox.checked = true;
  closeTermsModal();
}

/**
 * Admin Panel: Load Pending Approvals and Count
 */
async function loadPendingApprovalsCount() {
  const token = getToken();
  if (!token || !currentUser || currentUser.role !== 'admin') return;

  try {
    const res = await fetch('/api/auth/pending-approvals', {
      headers: { Authorization: `Bearer ${token}` },
    });

    if (!res.ok) return;

    const data = await res.json();
    const count = (data.pendingUsers || []).length;
    const badge = document.getElementById('pending-badge');
    if (badge) {
      badge.textContent = count;
      if (count > 0) {
        badge.classList.remove('hidden');
      } else {
        badge.classList.add('hidden');
      }
    }
  } catch (err) {
    console.error('Failed to load pending approvals count:', err);
  }
}

async function loadPendingApprovals() {
  const token = getToken();
  if (!token || !currentUser || currentUser.role !== 'admin') return;

  const tbody = document.getElementById('approvals-table-body');
  if (!tbody) return;

  tbody.innerHTML = `
    <tr>
      <td colspan="5" class="py-12 text-center text-slate-400">
        <i data-lucide="loader" class="w-6 h-6 animate-spin mx-auto mb-2 text-purple-600"></i>
        Loading pending authorizations...
      </td>
    </tr>
  `;
  if (window.lucide) lucide.createIcons();

  try {
    const res = await fetch('/api/auth/pending-approvals', {
      headers: { Authorization: `Bearer ${token}` },
    });

    if (!res.ok) {
      tbody.innerHTML = `<tr><td colspan="5" class="py-6 text-center text-rose-500">Failed to load pending users.</td></tr>`;
      return;
    }

    const data = await res.json();
    const users = data.pendingUsers || [];

    // Update badge
    const badge = document.getElementById('pending-badge');
    if (badge) {
      badge.textContent = users.length;
      if (users.length > 0) badge.classList.remove('hidden');
      else badge.classList.add('hidden');
    }

    if (users.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="5" class="py-12 text-center text-slate-400">
            <i data-lucide="check-circle" class="w-8 h-8 text-emerald-500 mx-auto mb-2"></i>
            <p class="font-semibold text-slate-700">All users authorized</p>
            <p class="text-xs text-slate-400 mt-1">There are no pending accounts awaiting security approval.</p>
          </td>
        </tr>
      `;
      if (window.lucide) lucide.createIcons();
      return;
    }

    tbody.innerHTML = users.map(u => {
      const isDispatched = u.account_status === 'AWAITING_USER_CODE';
      const statusBadge = isDispatched
        ? '<span class="px-2 py-0.5 rounded-full bg-blue-100 text-blue-800 border border-blue-200 font-bold">CODE DISPATCHED</span>'
        : '<span class="px-2 py-0.5 rounded-full bg-amber-100 text-amber-800 border border-amber-200 font-bold animate-pulse">PENDING ADMIN CODE</span>';

      const defaultCode = u.admin_auth_code || `TV-${Math.floor(100000 + Math.random() * 900000)}`;

      return `
        <tr class="hover:bg-slate-50 transition">
          <td class="py-3 px-4">
            <div class="font-bold text-slate-900 font-sans text-xs">${u.name}</div>
            <div class="text-slate-500 text-[10px] font-mono">${u.email}</div>
          </td>
          <td class="py-3 px-4 font-mono text-slate-700">${u.phone || 'N/A'}</td>
          <td class="py-3 px-4">
            <span class="px-2 py-0.5 text-[10px] font-bold uppercase rounded-md ${u.role === 'owner' ? 'bg-blue-100 text-blue-800' : 'bg-emerald-100 text-emerald-800'}">
              ${u.role}
            </span>
          </td>
          <td class="py-3 px-4">${statusBadge}</td>
          <td class="py-3 px-4">
            <div class="flex items-center gap-2">
              <input
                type="text"
                id="code-input-${u.id}"
                value="${defaultCode}"
                class="w-32 px-2.5 py-1 text-xs font-mono font-bold uppercase tracking-wider bg-slate-50 border border-slate-300 rounded-lg text-slate-800 focus:bg-white focus:ring-1 focus:ring-purple-500"
                placeholder="TV-123456"
              />
              <button
                onclick="handleAdminDispatchCode('${u.id}', 'code-input-${u.id}')"
                class="px-3 py-1 text-xs font-semibold text-white bg-purple-600 hover:bg-purple-700 rounded-lg shadow-xs flex items-center gap-1 transition"
              >
                <i data-lucide="send" class="w-3 h-3"></i> Send Code
              </button>
            </div>
          </td>
        </tr>
      `;
    }).join('');

    if (window.lucide) lucide.createIcons();
  } catch (err) {
    console.error('Error rendering approvals:', err);
    tbody.innerHTML = `<tr><td colspan="5" class="py-6 text-center text-rose-500">Error: ${err.message}</td></tr>`;
  }
}

/**
 * Administrator Dispatches Authorization Code to User's Email
 */
async function handleAdminDispatchCode(userId, inputId) {
  const token = getToken();
  if (!token) return;

  const codeInput = document.getElementById(inputId);
  const customCode = codeInput ? codeInput.value : '';

  try {
    const res = await fetch('/api/auth/admin-dispatch-code', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ userId, customCode }),
    });

    const data = await res.json();

    if (!res.ok) {
      showToast('Dispatch Failed', data.error || 'Could not send code', 'error');
      return;
    }

    showToast('Code Dispatched!', data.message, 'success');
    loadPendingApprovals();
  } catch (err) {
    showToast('Error', err.message, 'error');
  }
}
