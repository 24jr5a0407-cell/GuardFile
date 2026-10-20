// TrustVault Authentication & Multi-Step Zero-Trust Onboarding Module

// Defensively guarantee window.lucide stub to prevent ReferenceError
if (typeof window.lucide === 'undefined') {
  window.lucide = { createIcons: function() {} };
}

let currentUser = null;
let pendingRegistration = null; // { userId, email, phone, name, role }
let pending2FA = null;

/**
 * Universal Toast Notification Helper
 */
function showToast(title, message, type = 'info') {
  const toast = document.getElementById('toast');
  const toastTitle = document.getElementById('toast-title');
  const toastMsg = document.getElementById('toast-message');
  const toastIcon = document.getElementById('toast-icon');

  if (!toast) return;

  if (toastTitle) toastTitle.textContent = title;
  if (toastMsg) toastMsg.textContent = message;

  if (toastIcon) {
    if (type === 'success') {
      toastIcon.innerHTML = '<i data-lucide="check-circle" class="w-5 h-5 text-emerald-400"></i>';
    } else if (type === 'error') {
      toastIcon.innerHTML = '<i data-lucide="alert-triangle" class="w-5 h-5 text-rose-400"></i>';
    } else {
      toastIcon.innerHTML = '<i data-lucide="info" class="w-5 h-5 text-blue-400"></i>';
    }
  }

  try {
    if (typeof lucide !== 'undefined' && lucide && typeof lucide.createIcons === 'function') {
      lucide.createIcons();
    }
  } catch (e) {}

  toast.classList.remove('hidden');
  toast.style.display = 'flex';

  setTimeout(() => {
    toast.classList.add('hidden');
    toast.style.display = 'none';
  }, 4500);
}
window.showToast = showToast;

function getToken() {
  return localStorage.getItem('trustvault_token');
}

function setToken(token) {
  localStorage.setItem('trustvault_token', token);
}

function showAuthPortal() {
  const portal = document.getElementById('auth-portal-view');
  const dash = document.getElementById('main-dashboard-container');

  if (portal) {
    portal.classList.remove('hidden');
    portal.style.setProperty('display', 'flex', 'important');
  }
  if (dash) {
    dash.classList.add('hidden');
    dash.style.setProperty('display', 'none', 'important');
  }

  showPortalAuthTab('login');
  try {
    if (typeof lucide !== 'undefined' && lucide.createIcons) lucide.createIcons();
  } catch (e) {}
}

function showDashboard() {
  const portal = document.getElementById('auth-portal-view');
  const dash = document.getElementById('main-dashboard-container');

  if (portal) {
    portal.classList.add('hidden');
    portal.style.setProperty('display', 'none', 'important');
  }
  if (dash) {
    dash.classList.remove('hidden');
    dash.style.setProperty('display', 'flex', 'important');
  }

  closeGoogleModal();
  closeTermsModal();
  try {
    if (typeof lucide !== 'undefined' && lucide.createIcons) lucide.createIcons();
  } catch (e) {}
}

function clearSession() {
  localStorage.removeItem('trustvault_token');
  currentUser = null;
  pendingRegistration = null;
  pending2FA = null;
  renderAuthHeader();
  showAuthPortal();
  
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
    showAuthPortal();
    return;
  }

  try {
    const res = await fetch('/api/auth/me', {
      headers: { Authorization: `Bearer ${token}` },
    });

    if (res.ok) {
      const data = await res.json();
      currentUser = data.user;
      showDashboard();
      renderAuthHeader();
      if (typeof loadDocuments === 'function') loadDocuments();
      if (typeof updateStats === 'function') updateStats();
    } else {
      clearSession();
    }
  } catch (err) {
    console.error('Session check failed:', err);
    clearSession();
  }
}

/**
 * Quick Login helper for testing.
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
      handleAccountStatusResponse(data);
      return;
    }

    setToken(data.token);
    currentUser = data.user;
    showDashboard();
    renderAuthHeader();
    showToast('Authenticated', `Welcome back, ${currentUser.name}!`, 'success');
    if (typeof loadDocuments === 'function') loadDocuments();
    if (typeof updateStats === 'function') updateStats();
  } catch (err) {
    showToast('Error', err.message, 'error');
  }
}

/**
 * Renders Top Header Session View
 */
function renderAuthHeader() {
  const container = document.getElementById('auth-header-container');
  if (!container) return;

  if (!currentUser) {
    container.innerHTML = `
      <button onclick="showPortalAuthTab('login'); window.scrollTo({top: 0, behavior: 'smooth'});" class="px-4 py-2 text-xs font-bold text-white bg-blue-600 rounded-xl hover:bg-blue-700 shadow-sm transition cursor-pointer">
        Sign In
      </button>
    `;
    return;
  }

  const roleBadgeColor = {
    admin: 'bg-purple-100 text-purple-800 border-purple-200',
    owner: 'bg-blue-100 text-blue-800 border-blue-200',
    viewer: 'bg-emerald-100 text-emerald-800 border-emerald-200',
  }[currentUser.role] || 'bg-slate-100 text-slate-800 border-slate-200';

  // Toggle Admin Approvals Tab in Dashboard
  const adminTab = document.getElementById('tab-btn-approvals');
  if (adminTab) {
    if (currentUser.role === 'admin') {
      adminTab.classList.remove('hidden');
      loadPendingApprovalsCount();
    } else {
      adminTab.classList.add('hidden');
    }
  }

  // Get user initials
  const initials = (currentUser.name || 'User')
    .split(' ')
    .map(p => p[0])
    .join('')
    .substring(0, 2)
    .toUpperCase();

  container.innerHTML = `
    <div class="flex items-center gap-3">
      <div class="flex items-center gap-2 bg-slate-100/90 py-1 px-2.5 rounded-xl border border-slate-200">
        <div class="w-7 h-7 rounded-lg bg-blue-600 text-white font-bold flex items-center justify-center text-xs shadow-xs">
          ${initials}
        </div>
        <div class="flex flex-col text-left">
          <span class="text-xs font-bold text-slate-900 leading-tight">${currentUser.name}</span>
          <span class="text-[10px] text-slate-500 font-mono leading-tight">${currentUser.email}</span>
        </div>
        <span class="ml-1 text-[10px] font-extrabold uppercase px-2 py-0.5 rounded-full border ${roleBadgeColor}">
          ${currentUser.role}
        </span>
      </div>

      <button onclick="clearSession()" class="px-3 py-1.5 text-xs font-semibold text-slate-600 hover:text-rose-600 hover:bg-rose-50 rounded-xl transition cursor-pointer flex items-center gap-1.5" title="Sign Out">
        <i data-lucide="log-out" class="w-4 h-4"></i>
        <span class="hidden sm:inline">Sign Out</span>
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
 * Secret Admin Login autofill helper
 */
function fillAdminCredentials() {
  showPortalAuthTab('login');
  const emailInput = document.getElementById('portal-login-email');
  const passwordInput = document.getElementById('portal-login-password');
  if (emailInput) emailInput.value = 'guardfile@gmail.com';
  if (passwordInput) passwordInput.value = 'Arshad@1234';
  showToast('Admin Credentials Ready', 'Filled: guardfile@gmail.com / Arshad@1234', 'info');
}

/**
 * Portal View Tab Switching (Sign In vs Register vs OTP vs Admin Code)
 */
function showPortalAuthTab(tab) {
  const loginView = document.getElementById('portal-view-login');
  const registerView = document.getElementById('portal-view-register');
  const otpView = document.getElementById('portal-view-otp');
  const adminCodeView = document.getElementById('portal-view-admin-code');
  const tabBtnLogin = document.getElementById('portal-tab-btn-login');
  const tabBtnRegister = document.getElementById('portal-tab-btn-register');
  const tabHeader = document.getElementById('auth-portal-tab-header');

  // Explicitly hide all panels using both classes and inline styles
  [loginView, registerView, otpView, adminCodeView].forEach(el => {
    if (el) {
      el.classList.add('hidden');
      el.style.setProperty('display', 'none', 'important');
    }
  });

  if (tab === 'login') {
    if (tabHeader) { tabHeader.classList.remove('hidden'); tabHeader.style.display = 'flex'; }
    if (loginView) { loginView.classList.remove('hidden'); loginView.style.setProperty('display', 'flex', 'important'); }
    tabBtnLogin?.classList.add('active');
    tabBtnRegister?.classList.remove('active');
  } else if (tab === 'register') {
    if (tabHeader) { tabHeader.classList.remove('hidden'); tabHeader.style.display = 'flex'; }
    if (registerView) { registerView.classList.remove('hidden'); registerView.style.setProperty('display', 'flex', 'important'); }
    tabBtnRegister?.classList.add('active');
    tabBtnLogin?.classList.remove('active');
  } else if (tab === 'otp') {
    if (tabHeader) { tabHeader.classList.add('hidden'); tabHeader.style.display = 'none'; }
    if (otpView) { otpView.classList.remove('hidden'); otpView.style.setProperty('display', 'flex', 'important'); }
  } else if (tab === 'admin-code') {
    if (tabHeader) { tabHeader.classList.add('hidden'); tabHeader.style.display = 'none'; }
    if (adminCodeView) { adminCodeView.classList.remove('hidden'); adminCodeView.style.setProperty('display', 'flex', 'important'); }
  }

  try {
    if (typeof lucide !== 'undefined' && lucide.createIcons) lucide.createIcons();
  } catch (err) {}
}

function openLoginModal(initialTab = 'login') {
  showPortalAuthTab(initialTab);
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

function closeLoginModal() {}

function showAuthTab(tab) {
  showPortalAuthTab(tab);
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
    showPortalAuthTab('otp');
    const emailEl = document.getElementById('portal-otp-target-email');
    if (emailEl) emailEl.textContent = data.email;

    const statusEl = document.getElementById('portal-otp-status-text');
    if (statusEl) statusEl.textContent = data.message || 'Verification code dispatched to your email.';

    if (data.devOtp) {
      const devHint = document.getElementById('portal-otp-dev-hint');
      if (devHint) devHint.textContent = `Demo Verification Code: ${data.devOtp}`;
      const codeInput = document.getElementById('portal-otp-code-input');
      if (codeInput) codeInput.value = data.devOtp;
    }
  } else if (data.account_status === 'PENDING_ADMIN_CODE' || data.pendingAdminCode) {
    showPortalAuthTab('admin-code');
    const userEl = document.getElementById('portal-admin-code-user-info');
    if (userEl) userEl.textContent = `User: ${data.email}`;

    const pillEl = document.getElementById('portal-admin-code-status-pill');
    if (pillEl) pillEl.textContent = 'Awaiting Administrator Review';

    const noticeEl = document.getElementById('portal-admin-code-notice');
    if (noticeEl) {
      noticeEl.textContent =
        'Your email OTP is verified! Your System Administrator has been notified to generate your Access Authorization Code. When you receive it, enter it below.';
    }
  } else if (data.account_status === 'AWAITING_USER_CODE' || data.awaitingUserCode) {
    showPortalAuthTab('admin-code');
    const userEl = document.getElementById('portal-admin-code-user-info');
    if (userEl) userEl.textContent = `User: ${data.email}`;

    const pillEl = document.getElementById('portal-admin-code-status-pill');
    if (pillEl) pillEl.textContent = 'Code Sent to Your Email!';

    const noticeEl = document.getElementById('portal-admin-code-notice');
    if (noticeEl) {
      noticeEl.textContent =
        'The Administrator has dispatched your Authorization Code! Please check your email inbox and enter the code below to unlock your dashboard.';
    }
  }
}

/**
 * Handle Portal Login
 */
async function handlePortalLoginSubmit(e) {
  if (e) {
    if (typeof e.preventDefault === 'function') e.preventDefault();
    if (typeof e.stopPropagation === 'function') e.stopPropagation();
  }
  const emailInput = document.getElementById('portal-login-email');
  const passwordInput = document.getElementById('portal-login-password');
  const require2fa = document.getElementById('portal-login-require-2fa')?.checked || false;
  const errorEl = document.getElementById('portal-login-error');
  const submitBtn = document.getElementById('portal-login-submit-btn') || (e && e.target && e.target.querySelector ? e.target.querySelector('button[type="submit"]') : null);

  if (!emailInput || !passwordInput || !errorEl) return false;

  const email = emailInput.value.trim();
  const password = passwordInput.value;

  if (!email || !password) {
    errorEl.textContent = 'Please enter both your work email and password.';
    errorEl.classList.remove('hidden');
    return false;
  }

  errorEl.classList.add('hidden');
  const origBtnText = submitBtn ? submitBtn.innerHTML : 'Sign In to Vault';
  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.innerHTML = `
      <span class="inline-flex items-center justify-center gap-2">
        <svg class="animate-spin h-3.5 w-3.5 text-white" fill="none" viewBox="0 0 24 24">
          <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
          <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z"></path>
        </svg>
        Authenticating...
      </span>
    `;
  }

  try {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password, require2fa }),
    });

    const data = await res.json();

    if (!res.ok) {
      const msg = data.error || 'Invalid email or password.';
      errorEl.innerHTML = `
        <div class="flex flex-col gap-1 text-left">
          <span class="font-bold text-rose-700">${msg}</span>
          <span class="text-[11px] text-slate-600">
            No account registered with this email yet? 
            <button type="button" onclick="showPortalAuthTab('register')" class="text-blue-600 font-bold underline hover:text-blue-800 cursor-pointer">
              Click here to Create Account
            </button>
          </span>
        </div>
      `;
      errorEl.classList.remove('hidden');
      return false;
    }

    if (data.account_status && data.account_status !== 'ACTIVE') {
      handleAccountStatusResponse(data);
      return false;
    }

    if (data.require2FA) {
      pending2FA = data;
      showPortalAuthTab('otp');
      const targetEl = document.getElementById('portal-otp-target-email');
      if (targetEl) targetEl.textContent = data.email;
      const statusEl = document.getElementById('portal-otp-status-text');
      if (statusEl) statusEl.textContent = data.message;
      if (data.devOtp) {
        const devHint = document.getElementById('portal-otp-dev-hint');
        if (devHint) devHint.textContent = `Demo Code: ${data.devOtp}`;
        const codeInput = document.getElementById('portal-otp-code-input');
        if (codeInput) codeInput.value = data.devOtp;
      }
      return false;
    }

    setToken(data.token);
    currentUser = data.user;
    showDashboard();
    renderAuthHeader();
    showToast('Authenticated', `Welcome back, ${currentUser.name}!`, 'success');
    if (typeof loadDocuments === 'function') loadDocuments();
    if (typeof updateStats === 'function') updateStats();
  } catch (err) {
    errorEl.textContent = err.message;
    errorEl.classList.remove('hidden');
  } finally {
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.innerHTML = origBtnText;
    }
  }
  return false;
}

/**
 * Handle Portal Registration
 */
async function handlePortalRegisterSubmit(e) {
  if (e) {
    if (typeof e.preventDefault === 'function') e.preventDefault();
    if (typeof e.stopPropagation === 'function') e.stopPropagation();
  }
  const nameInput = document.getElementById('portal-reg-name');
  const emailInput = document.getElementById('portal-reg-email');
  const phoneInput = document.getElementById('portal-reg-phone');
  const passwordInput = document.getElementById('portal-reg-password');
  const confirmPasswordInput = document.getElementById('portal-reg-confirm-password');
  const termsInput = document.getElementById('portal-reg-terms');
  const errorEl = document.getElementById('portal-reg-error');
  const submitBtn = document.getElementById('portal-reg-submit-btn') || (e && e.target && e.target.querySelector ? e.target.querySelector('button[type="submit"]') : null);

  if (!nameInput || !emailInput || !phoneInput || !passwordInput || !confirmPasswordInput || !termsInput || !errorEl) return false;

  const name = nameInput.value.trim();
  const email = emailInput.value.trim();
  const phone = phoneInput.value.trim();
  const password = passwordInput.value;
  const confirmPassword = confirmPasswordInput.value;
  const roleInput = document.querySelector('input[name="portal-reg-role"]');
  const role = roleInput ? roleInput.value : 'viewer';
  const termsAccepted = termsInput.checked;

  errorEl.classList.add('hidden');

  if (!name || !email || !phone || !password) {
    errorEl.textContent = 'All fields marked with an asterisk (*) are required.';
    errorEl.classList.remove('hidden');
    return false;
  }

  if (password.length < 6) {
    errorEl.textContent = 'Password must be at least 6 characters long.';
    errorEl.classList.remove('hidden');
    return false;
  }

  if (password !== confirmPassword) {
    errorEl.textContent = 'Passwords do not match. Please verify.';
    errorEl.classList.remove('hidden');
    return false;
  }

  if (!termsAccepted) {
    errorEl.textContent = 'You must agree to the Terms of Service & Privacy Policy.';
    errorEl.classList.remove('hidden');
    return false;
  }

  const origBtnText = submitBtn ? submitBtn.innerHTML : 'Create Account & Verify OTP';
  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.innerHTML = `
      <span class="inline-flex items-center justify-center gap-2">
        <svg class="animate-spin h-3.5 w-3.5 text-white" fill="none" viewBox="0 0 24 24">
          <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
          <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z"></path>
        </svg>
        Creating Account...
      </span>
    `;
  }

  try {
    const res = await fetch('/api/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, email, phone, password, role, termsAccepted: true }),
    });

    const data = await res.json();

    if (!res.ok) {
      errorEl.textContent = data.error || 'Registration failed.';
      errorEl.classList.remove('hidden');
      return false;
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
  } finally {
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.innerHTML = origBtnText;
    }
  }
  return false;
}

/**
 * Handle Portal OTP Verification
 */
async function handlePortalOtpSubmit(e) {
  if (e) {
    if (typeof e.preventDefault === 'function') e.preventDefault();
    if (typeof e.stopPropagation === 'function') e.stopPropagation();
  }
  const code = document.getElementById('portal-otp-code-input').value.trim();
  const errorEl = document.getElementById('portal-otp-error');
  const submitBtn = document.getElementById('portal-otp-submit-btn') || (e && e.target && e.target.querySelector ? e.target.querySelector('button[type="submit"]') : null);

  errorEl.classList.add('hidden');

  const origBtnText = submitBtn ? submitBtn.innerHTML : 'Verify Email Code';
  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.innerHTML = `
      <span class="inline-flex items-center justify-center gap-2">
        <svg class="animate-spin h-3.5 w-3.5 text-white" fill="none" viewBox="0 0 24 24">
          <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
          <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z"></path>
        </svg>
        Verifying...
      </span>
    `;
  }

  try {
    if (pending2FA) {
      const res = await fetch('/api/auth/verify-2fa', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId: pending2FA.userId, otp: code }),
      });

      const data = await res.json();

      if (!res.ok) {
        errorEl.textContent = data.error || 'Invalid OTP code.';
        errorEl.classList.remove('hidden');
        return false;
      }

      setToken(data.token);
      currentUser = data.user;
      pending2FA = null;
      showDashboard();
      renderAuthHeader();
      showToast('2FA Verified', `Welcome back, ${currentUser.name}!`, 'success');
      if (typeof loadDocuments === 'function') loadDocuments();
      if (typeof updateStats === 'function') updateStats();
      return false;
    }

    if (!pendingRegistration) {
      errorEl.textContent = 'Session expired. Please restart registration.';
      errorEl.classList.remove('hidden');
      return false;
    }

    const res = await fetch('/api/auth/verify-registration-otp', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ userId: pendingRegistration.userId, otp: code }),
    });

    const data = await res.json();

    if (!res.ok) {
      errorEl.textContent = data.error || 'Verification code failed.';
      errorEl.classList.remove('hidden');
      return false;
    }

    showToast('Email Verified!', data.message, 'success');
    handleAccountStatusResponse(data);
  } catch (err) {
    errorEl.textContent = err.message;
    errorEl.classList.remove('hidden');
  } finally {
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.innerHTML = origBtnText;
    }
  }
  return false;
}

/**
 * Handle Portal Admin Code Submit
 */
async function handlePortalAdminCodeSubmit(e) {
  if (e) {
    if (typeof e.preventDefault === 'function') e.preventDefault();
    if (typeof e.stopPropagation === 'function') e.stopPropagation();
  }
  const code = document.getElementById('portal-admin-code-input').value.trim();
  const errorEl = document.getElementById('portal-admin-code-error');
  const submitBtn = document.getElementById('portal-admin-code-submit-btn') || (e && e.target && e.target.querySelector ? e.target.querySelector('button[type="submit"]') : null);

  errorEl.classList.add('hidden');

  if (!pendingRegistration) {
    errorEl.textContent = 'Session state missing. Please sign in again.';
    errorEl.classList.remove('hidden');
    return false;
  }

  const origBtnText = submitBtn ? submitBtn.innerHTML : 'Unlock Vault & Open Dashboard';
  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.innerHTML = `
      <span class="inline-flex items-center justify-center gap-2">
        <svg class="animate-spin h-3.5 w-3.5 text-white" fill="none" viewBox="0 0 24 24">
          <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
          <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z"></path>
        </svg>
        Validating Authorization...
      </span>
    `;
  }

  try {
    const res = await fetch('/api/auth/submit-admin-code', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ userId: pendingRegistration.userId, code }),
    });

    const data = await res.json();

    if (!res.ok) {
      errorEl.textContent = data.error || 'Invalid administrator authorization code.';
      errorEl.classList.remove('hidden');
      return false;
    }

    setToken(data.token);
    currentUser = data.user;
    pendingRegistration = null;
    showDashboard();
    renderAuthHeader();
    showToast('Vault Unlocked!', `Access granted. Welcome, ${currentUser.name}!`, 'success');
    if (typeof loadDocuments === 'function') loadDocuments();
    if (typeof updateStats === 'function') updateStats();
  } catch (err) {
    errorEl.textContent = err.message;
    errorEl.classList.remove('hidden');
  } finally {
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.innerHTML = origBtnText;
    }
  }
  return false;
}

/**
 * Check Admin Approval Status
 */
async function checkAdminApprovalStatus() {
  if (!pendingRegistration || !pendingRegistration.email) {
    showToast('No User Session', 'Please sign in or register first.', 'error');
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
 * Google Social Auth Flow
 */
function handleGoogleSignIn() {
  openGoogleModal();
}

function openGoogleModal() {
  document.getElementById('modal-google-auth')?.classList.remove('hidden');
  if (window.lucide) lucide.createIcons();
}

function closeGoogleModal() {
  document.getElementById('modal-google-auth')?.classList.add('hidden');
}

async function executeGoogleAuth(email, name, phone) {
  closeGoogleModal();
  showToast('Google OAuth', `Connecting with ${email}...`, 'info');

  try {
    const res = await fetch('/api/auth/google', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: email.trim(),
        name: name.trim(),
        phone: phone ? phone.trim() : null,
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
    showDashboard();
    renderAuthHeader();
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
  const termsCheckbox = document.getElementById('portal-reg-terms');
  if (termsCheckbox) termsCheckbox.checked = true;
  closeTermsModal();
}

/**
 * Admin Panel: Load Pending Approvals Count & Table
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
            <select
              id="role-select-${u.id}"
              class="px-2 py-1 text-xs font-semibold rounded-lg border border-slate-200 bg-white text-slate-800 focus:ring-1 focus:ring-purple-500 cursor-pointer shadow-xs"
            >
              <option value="owner" ${u.role === 'owner' ? 'selected' : ''}>Document Owner</option>
              <option value="viewer" ${u.role === 'viewer' ? 'selected' : ''}>Document Viewer</option>
            </select>
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
                onclick="handleAdminDispatchCode('${u.id}', 'code-input-${u.id}', 'role-select-${u.id}')"
                class="px-3 py-1 text-xs font-semibold text-white bg-purple-600 hover:bg-purple-700 rounded-lg shadow-xs flex items-center gap-1 transition cursor-pointer"
              >
                <i data-lucide="send" class="w-3 h-3"></i> Send Code
              </button>
            </div>
          </td>
        </tr>
      `;
    }).join('');

    try {
      if (typeof lucide !== 'undefined' && lucide.createIcons) lucide.createIcons();
    } catch (e) {}
  } catch (err) {
    console.error('Error rendering approvals:', err);
    tbody.innerHTML = `<tr><td colspan="5" class="py-6 text-center text-rose-500">Error: ${err.message}</td></tr>`;
  }
}

/**
 * Administrator Dispatches Authorization Code to User's Email and Assigns Role
 */
async function handleAdminDispatchCode(userId, inputId, roleSelectId) {
  const token = getToken();
  if (!token) return;

  const codeInput = document.getElementById(inputId);
  const roleSelect = roleSelectId ? document.getElementById(roleSelectId) : null;
  const customCode = codeInput ? codeInput.value : '';
  const assignedRole = roleSelect ? roleSelect.value : undefined;

  try {
    const res = await fetch('/api/auth/admin-dispatch-code', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ userId, customCode, assignedRole }),
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
