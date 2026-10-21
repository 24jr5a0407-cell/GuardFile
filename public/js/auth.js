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
  stopAdminNotificationPolling();
  stopUserApprovalPolling();
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
  initServiceWorker();
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
 * Renders Top Header Session View (iOS Human Interface Design)
 */
function renderAuthHeader() {
  const container = document.getElementById('auth-header-container');
  if (!container) return;

  if (!currentUser) {
    container.innerHTML = `
      <button onclick="showPortalAuthTab('login'); window.scrollTo({top: 0, behavior: 'smooth'});" class="px-4 py-2 text-xs font-bold text-white bg-blue-600 rounded-2xl hover:bg-blue-700 shadow-sm transition cursor-pointer">
        Sign In
      </button>
    `;
    return;
  }

  const isAdmin = currentUser.role === 'admin';

  // Toggle Admin Approvals Tab in Dashboard
  const adminTab = document.getElementById('tab-btn-approvals');
  if (adminTab) {
    if (isAdmin) {
      adminTab.classList.remove('hidden');
      startAdminNotificationPolling();
    } else {
      adminTab.classList.add('hidden');
      stopAdminNotificationPolling();
    }
  }

  // Get user initials
  const initials = (currentUser.name || 'User')
    .split(' ')
    .map(p => p[0])
    .join('')
    .substring(0, 2)
    .toUpperCase();

  // Mask admin identity on header for zero-trust executive stealth
  const displayEmail = isAdmin ? 'g***e@gmail.com' : currentUser.email;
  const displayName = isAdmin ? 'Master Administrator' : currentUser.name;
  const roleBadgeText = isAdmin ? 'Admin' : (currentUser.role === 'owner' ? 'Owner' : 'Viewer');
  const roleBadgeStyle = isAdmin 
    ? 'bg-purple-100 text-purple-800 border-purple-200' 
    : (currentUser.role === 'owner' ? 'bg-blue-100 text-blue-800 border-blue-200' : 'bg-emerald-100 text-emerald-800 border-emerald-200');

  // Unified Notification Bell
  const notifBellHtml = `
    <button 
      id="header-unified-notif-btn"
      onclick="handleUnifiedNotifClick()" 
      class="relative p-2 rounded-2xl text-slate-700 bg-white/90 hover:text-purple-700 hover:bg-purple-50 transition cursor-pointer flex items-center justify-center border border-slate-200/80 shadow-xs"
      title="Notifications & Security Alerts"
    >
      <i data-lucide="bell" class="w-4 h-4 text-purple-600"></i>
      <span id="header-admin-notif-badge" class="hidden absolute -top-1.5 -right-1.5 px-1.5 py-0.5 text-[9px] font-black rounded-full bg-rose-500 text-white animate-pulse">0</span>
    </button>
  `;

  container.innerHTML = `
    <div class="flex items-center gap-2">
      ${notifBellHtml}

      <div class="flex items-center gap-2.5 bg-slate-100/90 py-1 px-3 rounded-2xl border border-slate-200/80 shadow-xs">
        <div class="w-7 h-7 rounded-xl ${isAdmin ? 'ios-badge-purple' : 'ios-badge-blue'} text-white font-bold flex items-center justify-center text-xs shadow-xs">
          ${initials}
        </div>
        <div class="flex flex-col text-left">
          <span class="text-xs font-bold text-slate-900 leading-tight flex items-center gap-1">
            ${displayName}
            ${isAdmin ? '<i data-lucide="shield" class="w-3 h-3 text-purple-600"></i>' : ''}
          </span>
          <span class="text-[10px] text-slate-500 font-mono leading-tight">${displayEmail}</span>
        </div>
        <span class="ml-1 text-[10px] font-extrabold uppercase px-2 py-0.5 rounded-full border ${roleBadgeStyle}">
          ${roleBadgeText}
        </span>
      </div>

      <button onclick="openLogoutModal()" class="px-3 py-1.5 text-xs font-semibold text-slate-600 hover:text-rose-600 hover:bg-rose-50 rounded-2xl transition cursor-pointer flex items-center gap-1.5 border border-transparent hover:border-rose-200" title="Sign Out">
        <i data-lucide="log-out" class="w-4 h-4"></i>
        <span class="hidden sm:inline">Sign Out</span>
      </button>
    </div>
  `;

  // Hide upload and import buttons if Viewer
  const uploadBtn = document.getElementById('btn-open-upload');
  const importBtn = document.getElementById('btn-open-import');
  const isViewer = currentUser.role === 'viewer';
  if (uploadBtn) uploadBtn.style.display = isViewer ? 'none' : 'flex';
  if (importBtn) importBtn.style.display = isViewer ? 'none' : 'flex';

  if (window.lucide) lucide.createIcons();
}

/**
 * Unified notification click handler
 */
function handleUnifiedNotifClick() {
  if (currentUser?.role === 'admin') {
    switchTab('approvals');
  }
  toggleDesktopNotifications();
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
    stopUserApprovalPolling();
  } else if (tab === 'admin-code') {
    if (tabHeader) { tabHeader.classList.add('hidden'); tabHeader.style.display = 'none'; }
    if (adminCodeView) { adminCodeView.classList.remove('hidden'); adminCodeView.style.setProperty('display', 'flex', 'important'); }
    startUserApprovalPolling();
  } else {
    stopUserApprovalPolling();
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
  try {
    sessionStorage.setItem('trustvault_pending_reg', JSON.stringify(pendingRegistration));
  } catch (e) {}

  if (data.account_status === 'PENDING_OTP' || data.requireRegistrationOTP || data.requireOTP) {
    showPortalAuthTab('otp');
    const emailEl = document.getElementById('portal-otp-target-email');
    if (emailEl) emailEl.textContent = data.email || (pendingRegistration && pendingRegistration.email) || '';

    const statusEl = document.getElementById('portal-otp-status-text');
    if (statusEl) statusEl.textContent = data.message || 'Verification code dispatched to your email.';

    const devHint = document.getElementById('portal-otp-dev-hint');
    if (devHint) {
      devHint.textContent = '';
      devHint.style.display = 'none';
    }
    const codeInput = document.getElementById('portal-otp-code-input');
    if (codeInput) {
      codeInput.value = '';
      setTimeout(() => codeInput.focus(), 150);
    }
    startResendCooldown(30);
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
      pendingRegistration = null;
      showPortalAuthTab('otp');
      const targetEl = document.getElementById('portal-otp-target-email');
      if (targetEl) targetEl.textContent = data.email;
      const statusEl = document.getElementById('portal-otp-status-text');
      if (statusEl) statusEl.textContent = data.message || `Security verification code sent to ${data.email}`;
      const codeInput = document.getElementById('portal-otp-code-input');
      if (codeInput) codeInput.value = '';
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
      errorEl.textContent = data.details || data.error || 'Registration failed.';
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
    pending2FA = null;
    try {
      sessionStorage.setItem('trustvault_pending_reg', JSON.stringify(pendingRegistration));
    } catch (e) {}

    showToast('Account Created', `A 6-digit verification OTP has been sent to ${data.email}.`, 'success');
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

  if (!code || code.length !== 6) {
    errorEl.textContent = 'Please enter the complete 6-digit verification code.';
    errorEl.classList.remove('hidden');
    return false;
  }

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
    // Check if we have an active pending registration
    if (!pendingRegistration) {
      try {
        const stored = sessionStorage.getItem('trustvault_pending_reg');
        if (stored) pendingRegistration = JSON.parse(stored);
      } catch (e) {}
    }

    if (pendingRegistration && pendingRegistration.userId) {
      const res = await fetch('/api/auth/verify-registration-otp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId: pendingRegistration.userId, otpCode: code, otp: code }),
      });

      const data = await res.json();

      if (!res.ok) {
        errorEl.textContent = data.error || 'Verification code failed. Please check the code in your email.';
        errorEl.classList.remove('hidden');
        return false;
      }

      showToast('Email Verified!', data.message, 'success');
      handleAccountStatusResponse(data);
      return false;
    }

    // Otherwise, check if this is a login 2FA verification
    if (pending2FA && pending2FA.userId) {
      const res = await fetch('/api/auth/verify-otp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId: pending2FA.userId, otpCode: code, otp: code }),
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

    errorEl.textContent = 'Verification session expired. Please sign in or register again.';
    errorEl.classList.remove('hidden');
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

let resendTimerInterval = null;
let resendSecondsRemaining = 0;

function startResendCooldown(seconds = 30) {
  const resendBtn = document.getElementById('portal-otp-resend-btn');
  const resendLabel = document.getElementById('portal-otp-resend-label');
  const resendIcon = document.getElementById('portal-otp-resend-icon');
  if (!resendBtn || !resendLabel) return;

  clearInterval(resendTimerInterval);
  resendSecondsRemaining = seconds;
  resendBtn.disabled = true;

  const updateUI = () => {
    if (resendSecondsRemaining > 0) {
      resendLabel.textContent = `Resend in ${resendSecondsRemaining}s`;
      resendSecondsRemaining--;
    } else {
      clearInterval(resendTimerInterval);
      resendTimerInterval = null;
      resendBtn.disabled = false;
      resendLabel.textContent = 'Resend Code';
      if (resendIcon) resendIcon.classList.remove('animate-spin');
    }
  };

  updateUI();
  resendTimerInterval = setInterval(updateUI, 1000);
}

/**
 * Resends a fresh OTP code to the registered email with cooldown and anti-spam protection
 */
async function triggerResendOtp() {
  if (resendSecondsRemaining > 0) return;

  const resendBtn = document.getElementById('portal-otp-resend-btn');
  const resendLabel = document.getElementById('portal-otp-resend-label');
  const resendIcon = document.getElementById('portal-otp-resend-icon');

  let target = pendingRegistration;
  if (!target) {
    try {
      const stored = sessionStorage.getItem('trustvault_pending_reg');
      if (stored) target = JSON.parse(stored);
    } catch (e) {}
  }

  if (!target && pending2FA) {
    target = pending2FA;
  }

  if (!target || (!target.userId && !target.email)) {
    showToast('Session Expired', 'Please enter your email and register again.', 'warning');
    showPortalAuthTab('register');
    return;
  }

  if (resendBtn) resendBtn.disabled = true;
  if (resendIcon) resendIcon.classList.add('animate-spin');
  if (resendLabel) resendLabel.textContent = 'Sending...';

  try {
    const res = await fetch('/api/auth/resend-registration-otp', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ userId: target.userId, email: target.email }),
    });

    const data = await res.json();

    if (!res.ok) {
      if (res.status === 429) {
        startResendCooldown(data.waitSec || 15);
        showToast('Please Wait', data.error, 'warning');
      } else {
        showToast('Resend Failed', data.error || 'Failed to dispatch code.', 'error');
        if (resendBtn) resendBtn.disabled = false;
        if (resendLabel) resendLabel.textContent = 'Resend Code';
        if (resendIcon) resendIcon.classList.remove('animate-spin');
      }
      return;
    }

    showToast('Code Dispatched!', data.message || `Fresh verification code sent to ${target.email}`, 'success');
    const statusText = document.getElementById('portal-otp-status-text');
    if (statusText) statusText.textContent = `Fresh code dispatched to ${target.email}. Please check your Inbox and Spam folders.`;

    // Clear input so user types fresh code
    const codeInput = document.getElementById('portal-otp-code-input');
    if (codeInput) {
      codeInput.value = '';
      codeInput.focus();
    }

    startResendCooldown(data.cooldownSeconds || 30);
  } catch (err) {
    showToast('Error', err.message, 'error');
    if (resendBtn) resendBtn.disabled = false;
    if (resendLabel) resendLabel.textContent = 'Resend Code';
    if (resendIcon) resendIcon.classList.remove('animate-spin');
  }
}

// Backward-compatible alias
const resendRegistrationOtp = triggerResendOtp;

let userApprovalPollInterval = null;

function startUserApprovalPolling() {
  stopUserApprovalPolling();
  userApprovalPollInterval = setInterval(async () => {
    let target = pendingRegistration;
    if (!target) {
      try {
        const stored = sessionStorage.getItem('trustvault_pending_reg');
        if (stored) target = JSON.parse(stored);
      } catch (e) {}
    }
    if (!target || (!target.userId && !target.email)) return;

    try {
      const res = await fetch('/api/auth/registration-status', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId: target.userId, email: target.email }),
      });
      if (!res.ok) return;
      const data = await res.json();

      if (data.account_status === 'AWAITING_USER_CODE' || data.hasAdminCode) {
        stopUserApprovalPolling();
        const noticeEl = document.getElementById('portal-admin-code-notice');
        if (noticeEl) {
          noticeEl.innerHTML = `
            <span class="text-emerald-700 font-bold block mb-1">🎉 Authorization Code Dispatched!</span>
            <span>The Administrator has approved your account and sent your code to <strong>${target.email}</strong>. Check your inbox (or spam) and enter it below.</span>
          `;
        }
        const pillEl = document.getElementById('portal-admin-code-status-pill');
        if (pillEl) {
          pillEl.className = 'inline-block mt-1 px-2.5 py-0.5 rounded-full text-[10px] font-bold bg-emerald-100 text-emerald-800 border border-emerald-200';
          pillEl.textContent = 'Code Sent to Your Email!';
        }
        showToast('Code Ready!', `The Administrator has dispatched your code to ${target.email}.`, 'success');
        triggerDeviceNotification('GuardFile: Access Code Ready!', `The Administrator has dispatched your Authorization Code to ${target.email}.`);
        const codeInput = document.getElementById('portal-admin-code-input');
        if (codeInput) {
          codeInput.focus();
        }
      }
    } catch (e) {}
  }, 4000);
}

function stopUserApprovalPolling() {
  if (userApprovalPollInterval) {
    clearInterval(userApprovalPollInterval);
    userApprovalPollInterval = null;
  }
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

  let target = pendingRegistration;
  if (!target) {
    try {
      const stored = sessionStorage.getItem('trustvault_pending_reg');
      if (stored) target = JSON.parse(stored);
    } catch (e) {}
  }

  if (!target || !target.userId) {
    errorEl.textContent = 'Registration session expired. Please sign in or register again.';
    errorEl.classList.remove('hidden');
    return false;
  }

  if (!code) {
    errorEl.textContent = 'Please enter the authorization code sent to your email.';
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
    const res = await fetch('/api/auth/verify-admin-code', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ userId: target.userId, authCode: code, code }),
    });

    const data = await res.json();

    if (!res.ok) {
      errorEl.textContent = data.error || 'Invalid administrator authorization code.';
      errorEl.classList.remove('hidden');
      return false;
    }

    stopUserApprovalPolling();
    try { sessionStorage.removeItem('trustvault_pending_reg'); } catch (e) {}
    setToken(data.token);
    currentUser = data.user;
    pendingRegistration = null;
    showDashboard();
    renderAuthHeader();
    showToast('Vault Unlocked!', `Access granted. Welcome, ${currentUser.name} (${currentUser.role.toUpperCase()})!`, 'success');
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
async function checkAdminApprovalStatus(silent = false) {
  let target = pendingRegistration;
  if (!target) {
    try {
      const stored = sessionStorage.getItem('trustvault_pending_reg');
      if (stored) target = JSON.parse(stored);
    } catch (e) {}
  }

  if (!target || (!target.userId && !target.email)) {
    if (!silent) showToast('No User Session', 'Please sign in or register first.', 'error');
    return;
  }

  try {
    const res = await fetch('/api/auth/registration-status', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ userId: target.userId, email: target.email }),
    });

    const data = await res.json();

    if (data.account_status === 'AWAITING_USER_CODE' || data.hasAdminCode) {
      const noticeEl = document.getElementById('portal-admin-code-notice');
      if (noticeEl) {
        noticeEl.innerHTML = `
          <span class="text-emerald-700 font-bold block mb-1">🎉 Authorization Code Dispatched!</span>
          <span>The Administrator has approved your account and dispatched your code to <strong>${target.email}</strong>. Check your inbox and enter it below.</span>
        `;
      }
      const pillEl = document.getElementById('portal-admin-code-status-pill');
      if (pillEl) {
        pillEl.className = 'inline-block mt-1 px-2.5 py-0.5 rounded-full text-[10px] font-bold bg-emerald-100 text-emerald-800 border border-emerald-200';
        pillEl.textContent = 'Code Sent to Your Email!';
      }
      if (!silent) showToast('Code Ready!', `The Administrator has dispatched your code to ${target.email}.`, 'success');
      const codeInput = document.getElementById('portal-admin-code-input');
      if (codeInput) codeInput.focus();
    } else {
      if (!silent) showToast('Status Checked', 'Still awaiting Administrator action.', 'info');
    }
  } catch (err) {
    console.error('Check status error:', err);
  }
}

/**
 * Official Google Sign-In & Enterprise Identity Integration
 */
function initGoogleIdentity() {
  if (typeof google !== 'undefined' && google.accounts && google.accounts.id) {
    try {
      google.accounts.id.initialize({
        client_id: '718873617382-sample.apps.googleusercontent.com',
        callback: handleGoogleCredentialResponse,
        auto_select: false,
        cancel_on_tap_outside: true,
      });

      const btnContainer = document.getElementById('google-gsi-button');
      if (btnContainer) {
        google.accounts.id.renderButton(btnContainer, {
          theme: 'outline',
          size: 'large',
          shape: 'pill',
          width: '100%',
          text: 'continue_with',
        });
      }
    } catch (e) {
      console.warn('Google Identity initialization deferred:', e);
    }
  }
}

function handleGoogleCredentialResponse(response) {
  if (!response || !response.credential) return;
  try {
    const base64Url = response.credential.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = decodeURIComponent(atob(base64).split('').map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2)).join(''));
    const payload = JSON.parse(jsonPayload);

    if (payload.email) {
      executeGoogleAuth(payload.email, payload.name || payload.email.split('@')[0]);
    }
  } catch (err) {
    console.error('Failed to parse Google credential:', err);
    showToast('Sign-In Error', 'Unable to process Google credential.', 'error');
  }
}

function handleGoogleSignIn() {
  if (typeof google !== 'undefined' && google.accounts && google.accounts.id) {
    try {
      google.accounts.id.prompt((notification) => {
        if (notification.isNotDisplayed() || notification.isSkippedMoment()) {
          openGoogleModal();
        }
      });
      return;
    } catch (e) {}
  }
  openGoogleModal();
}

function handleGoogleDirectEmailSubmit(e) {
  if (e && e.preventDefault) e.preventDefault();
  const emailInput = document.getElementById('google-direct-email-input');
  if (!emailInput || !emailInput.value.trim()) return;

  const email = emailInput.value.trim().toLowerCase();
  const name = email.split('@')[0];

  executeGoogleAuth(email, name);
}

function openGoogleModal() {
  const modal = document.getElementById('modal-google-auth');
  if (modal) {
    const input = document.getElementById('google-direct-email-input');
    if (input) {
      input.value = '';
      setTimeout(() => input.focus(), 150);
    }
    modal.classList.remove('hidden');
    modal.style.setProperty('display', 'flex', 'important');
  }
  if (typeof initGoogleIdentity === 'function') initGoogleIdentity();
  if (window.lucide) lucide.createIcons();
}

function closeGoogleModal() {
  const modal = document.getElementById('modal-google-auth');
  if (modal) {
    modal.classList.add('hidden');
    modal.style.setProperty('display', 'none', 'important');
  }
}

async function executeGoogleAuth(email, name, phone) {
  closeGoogleModal();
  showToast('Connecting', `Authenticating session for ${email}...`, 'info');

  try {
    const res = await fetch('/api/auth/google', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: email.trim(),
        name: name ? name.trim() : email.split('@')[0],
        phone: phone ? phone.trim() : null,
        role: 'owner',
      }),
    });

    const data = await res.json();
    if (!res.ok) {
      showToast('Authentication Refused', data.error || 'Failed to authenticate.', 'error');
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
    triggerDeviceNotification('Welcome to GuardFile!', `Authenticated via Google as ${currentUser.name}.`);
    if (typeof loadDocuments === 'function') loadDocuments();
    if (typeof updateStats === 'function') updateStats();
  } catch (err) {
    showToast('Connection Error', err.message, 'error');
  }
}

// Attach Google auth functions globally to window
window.handleGoogleSignIn = handleGoogleSignIn;
window.openGoogleModal = openGoogleModal;
window.closeGoogleModal = closeGoogleModal;
window.executeGoogleAuth = executeGoogleAuth;
window.handleGoogleDirectEmailSubmit = handleGoogleDirectEmailSubmit;
window.loadPendingApprovals = loadPendingApprovals;
window.loadAllUsers = loadAllUsers;

/**
 * Web Audio Chime Notification Helper
 */
function playNotificationSound() {
  try {
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.connect(gain);
    gain.connect(ctx.destination);
    osc.type = 'sine';
    osc.frequency.setValueAtTime(587.33, ctx.currentTime); // D5
    osc.frequency.setValueAtTime(783.99, ctx.currentTime + 0.12); // G5
    gain.gain.setValueAtTime(0.12, ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.35);
    osc.start(ctx.currentTime);
    osc.stop(ctx.currentTime + 0.35);
  } catch (e) {}
}

/**
 * Native OS / Desktop Notification Dispatcher
 */
async function triggerDeviceNotification(title, body, tag = 'guardfile') {
  playNotificationSound();
  if (!('Notification' in window)) return;
  if (Notification.permission === 'granted') {
    try {
      if ('serviceWorker' in navigator && navigator.serviceWorker.controller) {
        const reg = await navigator.serviceWorker.ready;
        reg.showNotification(title, {
          body,
          icon: 'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="%232563eb"><path d="M12 2L3 7v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7l-9-5z"/></svg>',
          badge: 'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="%232563eb"><path d="M12 2L3 7v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7l-9-5z"/></svg>',
          vibrate: [200, 100, 200],
          tag,
          requireInteraction: true,
        });
        return;
      }
    } catch (e) {}
    try {
      new Notification(title, {
        body,
        icon: 'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="%232563eb"><path d="M12 2L3 7v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7l-9-5z"/></svg>',
        tag,
      });
    } catch (e) {}
  }
}

/**
 * Toggle / Request Desktop Notification Permissions
 */
async function toggleDesktopNotifications() {
  if (!('Notification' in window)) {
    showToast('Not Supported', 'Desktop notifications are not supported by this browser.', 'warning');
    return;
  }

  if (Notification.permission === 'granted') {
    showToast('Notifications Active', 'Desktop notifications are active on this device.', 'info');
    triggerDeviceNotification('GuardFile Notifications Active', 'You are ready to receive real-time alerts even when minimized.');
    updateNotificationPermissionUI();
    return;
  }

  if (Notification.permission === 'denied') {
    showToast('Notifications Blocked', 'Please click the lock/tune icon near your browser address bar and set Notifications to "Allow".', 'warning');
    return;
  }

  try {
    const permission = await Notification.requestPermission();
    if (permission === 'granted') {
      showToast('Notifications Enabled!', 'You will now receive security alerts when codes and approvals are issued.', 'success');
      triggerDeviceNotification('GuardFile Notifications Enabled', 'You will receive real-time alerts when approvals or access codes arrive.');
    } else {
      showToast('Notifications Denied', 'Desktop notifications were not enabled.', 'info');
    }
  } catch (err) {
    console.error('Notification request error:', err);
  }
  updateNotificationPermissionUI();
}

function updateNotificationPermissionUI() {
  const dot = document.getElementById('notif-permission-dot');
  if (dot) {
    if ('Notification' in window && Notification.permission === 'granted') {
      dot.classList.remove('hidden');
    } else {
      dot.classList.add('hidden');
    }
  }
}

function initServiceWorker() {
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/sw.js').then((reg) => {
      console.log('[ServiceWorker] Active with scope:', reg.scope);
    }).catch((err) => {
      console.warn('[ServiceWorker] Registration notice:', err.message);
    });
  }
  updateNotificationPermissionUI();
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

let previousPendingCount = -1;
let adminNotifPollInterval = null;

function startAdminNotificationPolling() {
  stopAdminNotificationPolling();
  loadPendingApprovalsCount();
  adminNotifPollInterval = setInterval(() => {
    if (currentUser && currentUser.role === 'admin') {
      loadPendingApprovalsCount();
    }
  }, 6000);
}

function stopAdminNotificationPolling() {
  if (adminNotifPollInterval) {
    clearInterval(adminNotifPollInterval);
    adminNotifPollInterval = null;
  }
}

function generateNewAdminCode(userId) {
  const input = document.getElementById(`code-input-${userId}`);
  if (input) {
    input.value = `GF-${Math.floor(100000 + Math.random() * 900000)}`;
    input.focus();
  }
}

async function handleAdminDispatchCode(userId, inputId, roleSelectId) {
  const token = getToken();
  if (!token) {
    showToast('Unauthorized', 'Please sign in as Administrator.', 'error');
    return;
  }

  const inputEl = document.getElementById(inputId);
  const roleSelectEl = document.getElementById(roleSelectId);
  const dispatchBtn = document.getElementById(`dispatch-btn-${userId}`);

  const customCode = inputEl ? inputEl.value.trim().toUpperCase() : '';
  const assignedRole = roleSelectEl ? roleSelectEl.value : 'viewer';

  if (!customCode) {
    showToast('Code Missing', 'Please enter or generate an authorization code first.', 'warning');
    if (inputEl) inputEl.focus();
    return;
  }

  const origBtnHtml = dispatchBtn ? dispatchBtn.innerHTML : 'Send Code';
  if (dispatchBtn) {
    dispatchBtn.disabled = true;
    dispatchBtn.innerHTML = '<i data-lucide="loader" class="w-3 h-3 animate-spin"></i> Sending...';
    if (window.lucide) lucide.createIcons();
  }

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
      showToast('Dispatch Failed', data.error || 'Failed to dispatch code.', 'error');
      if (dispatchBtn) {
        dispatchBtn.disabled = false;
        dispatchBtn.innerHTML = origBtnHtml;
        if (window.lucide) lucide.createIcons();
      }
      return;
    }

    showToast('Code Dispatched!', data.message || `Code successfully dispatched to user!`, 'success');
    await loadPendingApprovals();
    if (typeof loadAllUsers === 'function') await loadAllUsers();
    if (typeof loadAuditLogs === 'function') loadAuditLogs();
    if (typeof updateStats === 'function') updateStats();
  } catch (err) {
    showToast('Dispatch Error', err.message, 'error');
    if (dispatchBtn) {
      dispatchBtn.disabled = false;
      dispatchBtn.innerHTML = origBtnHtml;
      if (window.lucide) lucide.createIcons();
    }
  }
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
    
    // Update tab badge
    const badge = document.getElementById('pending-badge');
    if (badge) {
      badge.textContent = count;
      if (count > 0) badge.classList.remove('hidden');
      else badge.classList.add('hidden');
    }

    // Update header notification bell badge
    const headerBadge = document.getElementById('header-admin-notif-badge');
    if (headerBadge) {
      headerBadge.textContent = count;
      if (count > 0) headerBadge.classList.remove('hidden');
      else headerBadge.classList.add('hidden');
    }

    // Notify admin if new users just arrived
    if (previousPendingCount !== -1 && count > previousPendingCount) {
      showToast('New User Awaiting Approval!', `${count} user(s) verified OTP and are waiting for your Authorization Code.`, 'info');
      triggerDeviceNotification('GuardFile: User Awaiting Approval', `${count} user(s) verified OTP and are waiting for your Authorization Code.`, 'admin-pending-approval');
      const approvalsView = document.getElementById('view-approvals');
      if (approvalsView && !approvalsView.classList.contains('hidden')) {
        loadPendingApprovals();
      }
    }
    previousPendingCount = count;
  } catch (err) {
    console.error('Failed to load pending approvals count:', err);
  }
}

let _cachedPendingUsers = [];

async function loadPendingApprovals() {
  const token = getToken();
  if (!token || !currentUser || currentUser.role !== 'admin') return;

  const tbody = document.getElementById('approvals-table-body');
  if (!tbody) return;

  tbody.innerHTML = `
    <tr>
      <td colspan="5" class="py-12 text-center text-slate-400 font-sans">
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
      tbody.innerHTML = `<tr><td colspan="5" class="py-6 text-center text-rose-500 font-sans">Failed to load pending users.</td></tr>`;
      return;
    }

    const data = await res.json();
    _cachedPendingUsers = data.pendingUsers || [];

    const badge = document.getElementById('pending-badge');
    if (badge) {
      badge.textContent = _cachedPendingUsers.length;
      if (_cachedPendingUsers.length > 0) badge.classList.remove('hidden');
      else badge.classList.add('hidden');
    }

    const headerBadge = document.getElementById('header-admin-notif-badge');
    if (headerBadge) {
      headerBadge.textContent = _cachedPendingUsers.length;
      if (_cachedPendingUsers.length > 0) headerBadge.classList.remove('hidden');
      else headerBadge.classList.add('hidden');
    }

    renderApprovalsTable(_cachedPendingUsers);
  } catch (err) {
    console.error('Error loading pending approvals:', err);
    tbody.innerHTML = `<tr><td colspan="5" class="py-6 text-center text-rose-500 font-sans">Error: ${err.message}</td></tr>`;
  }
}

function renderApprovalsTable(users) {
  const tbody = document.getElementById('approvals-table-body');
  if (!tbody) return;

  if (users.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="5" class="py-12 text-center text-slate-400 font-sans">
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

    const defaultCode = u.admin_auth_code || `GF-${Math.floor(100000 + Math.random() * 900000)}`;

    return `
      <tr class="hover:bg-slate-50 transition">
        <td class="py-3.5 px-4">
          <div class="font-bold text-slate-900 font-sans text-xs">${u.name}</div>
          <div class="text-slate-500 text-[10px] font-mono">${u.email}</div>
        </td>
        <td class="py-3.5 px-4 font-mono text-slate-700">${u.phone || 'N/A'}</td>
        <td class="py-3.5 px-4">
          <select
            id="role-select-${u.id}"
            class="px-2.5 py-1 text-xs font-semibold rounded-lg border border-slate-200 bg-white text-slate-800 focus:ring-1 focus:ring-purple-500 cursor-pointer shadow-xs"
          >
            <option value="owner" ${u.role === 'owner' ? 'selected' : ''}>Document Owner</option>
            <option value="viewer" ${u.role === 'viewer' ? 'selected' : ''}>Document Viewer</option>
          </select>
        </td>
        <td class="py-3.5 px-4">${statusBadge}</td>
        <td class="py-3.5 px-4">
          <div class="flex items-center gap-1.5">
            <input
              type="text"
              id="code-input-${u.id}"
              value="${defaultCode}"
              class="w-32 px-2.5 py-1 text-xs font-mono font-bold uppercase tracking-wider bg-slate-50 border border-slate-300 rounded-lg text-slate-800 focus:bg-white focus:ring-1 focus:ring-purple-500"
              placeholder="GF-123456"
            />
            <button
              type="button"
              onclick="generateNewAdminCode('${u.id}')"
              title="Generate fresh code"
              class="p-1 rounded-lg text-slate-400 hover:text-purple-600 hover:bg-purple-50 transition cursor-pointer"
            >
              <i data-lucide="sparkles" class="w-3.5 h-3.5"></i>
            </button>
            <button
              id="dispatch-btn-${u.id}"
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

  if (window.lucide) lucide.createIcons();
}

function handleApprovalsSearch(query) {
  const q = (query || '').toLowerCase().trim();
  if (!q) {
    renderApprovalsTable(_cachedPendingUsers);
    return;
  }
  const filtered = _cachedPendingUsers.filter(u => {
    return (
      (u.name && u.name.toLowerCase().includes(q)) ||
      (u.email && u.email.toLowerCase().includes(q)) ||
      (u.phone && u.phone.toLowerCase().includes(q)) ||
      (u.role && u.role.toLowerCase().includes(q))
    );
  });
  renderApprovalsTable(filtered);
}

let _cachedAllUsers = [];

/**
 * Admin Panel: Load All System Users & Manage Roles
 */
async function loadAllUsers() {
  const token = getToken();
  if (!token || !currentUser || currentUser.role !== 'admin') return;

  const tbody = document.getElementById('all-users-table-body');
  if (!tbody) return;

  tbody.innerHTML = `
    <tr>
      <td colspan="6" class="py-8 text-center text-slate-400 font-sans">
        <i data-lucide="loader" class="w-5 h-5 animate-spin mx-auto mb-1 text-blue-600"></i>
        Loading user directory...
      </td>
    </tr>
  `;
  if (window.lucide) lucide.createIcons();

  try {
    const res = await fetch('/api/auth/users', {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) {
      tbody.innerHTML = `<tr><td colspan="6" class="py-6 text-center text-rose-500 font-sans">Failed to load user directory.</td></tr>`;
      return;
    }
    const data = await res.json();
    _cachedAllUsers = data.users || [];
    renderUserDirectoryTable(_cachedAllUsers);
  } catch (err) {
    console.error('Failed to load users directory:', err);
    tbody.innerHTML = `<tr><td colspan="6" class="py-6 text-center text-rose-500 font-sans">Error: ${err.message}</td></tr>`;
  }
}

function renderUserDirectoryTable(users) {
  const tbody = document.getElementById('all-users-table-body');
  if (!tbody) return;

  if (users.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" class="py-6 text-center text-slate-400 font-sans">No users registered yet.</td></tr>`;
    return;
  }

  tbody.innerHTML = users.map(u => {
    const isSelf = u.id === currentUser.id;
    const isAdmin = u.role === 'admin';

    let statusBadge = '<span class="px-2 py-0.5 rounded-full bg-emerald-100 text-emerald-800 border border-emerald-200 font-bold text-[10px]">ACTIVE</span>';
    if (u.account_status === 'AWAITING_ADMIN_APPROVAL' || u.account_status === 'PENDING_ADMIN_CODE') {
      statusBadge = '<span class="px-2 py-0.5 rounded-full bg-amber-100 text-amber-800 border border-amber-200 font-bold text-[10px] animate-pulse">AWAITING CODE</span>';
    } else if (u.account_status === 'AWAITING_USER_CODE') {
      statusBadge = '<span class="px-2 py-0.5 rounded-full bg-blue-100 text-blue-800 border border-blue-200 font-bold text-[10px]">CODE DISPATCHED</span>';
    } else if (u.account_status === 'PENDING_OTP') {
      statusBadge = '<span class="px-2 py-0.5 rounded-full bg-slate-100 text-slate-700 border border-slate-200 font-bold text-[10px]">PENDING OTP</span>';
    }

    const assignedCodeHtml = u.admin_auth_code 
      ? `<div class="mt-1 flex items-center gap-1 font-mono text-[10px] text-purple-700 bg-purple-50 px-2 py-0.5 rounded border border-purple-200 w-fit" title="Assigned Authorization Code"><i data-lucide="key" class="w-3 h-3 text-purple-500"></i> ${u.admin_auth_code}</div>`
      : `<div class="mt-1 text-[10px] text-slate-400 font-mono">—</div>`;

    return `
      <tr class="hover:bg-slate-50 transition">
        <td class="py-3.5 px-4">
          <div class="font-bold text-slate-900 font-sans text-xs flex items-center gap-1.5">
            ${u.name}
            ${isSelf ? '<span class="text-[10px] bg-purple-100 text-purple-700 font-bold px-1.5 py-0.5 rounded-md border border-purple-200">You</span>' : ''}
          </div>
          <div class="text-slate-500 text-[10px] font-mono">${u.email}</div>
        </td>
        <td class="py-3.5 px-4 font-mono text-slate-700">${u.phone || '—'}</td>
        <td class="py-3.5 px-4">
          ${statusBadge}
        </td>
        <td class="py-3.5 px-4">
          ${isAdmin ? `
            <span class="px-2.5 py-1 rounded-lg bg-purple-100 text-purple-800 border border-purple-200 font-bold text-xs inline-flex items-center gap-1 font-sans">
              <i data-lucide="shield" class="w-3 h-3 text-purple-600"></i> Administrator
            </span>
          ` : `
            <select
              id="role-change-${u.id}"
              class="px-2.5 py-1 text-xs font-semibold rounded-lg border border-slate-200 bg-white text-slate-800 focus:ring-1 focus:ring-blue-500 cursor-pointer shadow-xs"
            >
              <option value="owner" ${u.role === 'owner' ? 'selected' : ''}>Document Owner</option>
              <option value="viewer" ${u.role === 'viewer' ? 'selected' : ''}>Document Viewer</option>
            </select>
          `}
        </td>
        <td class="py-3.5 px-4">
          ${isAdmin ? `
            <span class="text-xs text-slate-400 font-sans">Master Authority</span>
          ` : `
            <button
              type="button"
              id="del-perm-btn-${u.id}"
              onclick="handleToggleDeletePermission('${u.id}', ${!u.can_delete})"
              class="px-2.5 py-1 text-[11px] font-semibold rounded-lg border transition cursor-pointer flex items-center gap-1 ${u.can_delete ? 'bg-emerald-50 text-emerald-700 border-emerald-200 hover:bg-emerald-100' : 'bg-slate-100 text-slate-600 border-slate-200 hover:bg-slate-200'}"
              title="Toggle File Deletion Privilege"
            >
              <i data-lucide="${u.can_delete ? 'check' : 'lock'}" class="w-3 h-3"></i>
              ${u.can_delete ? 'Allowed' : 'Restricted'}
            </button>
          `}
        </td>
        <td class="py-3.5 px-4">
          ${isAdmin ? `<span class="text-xs text-slate-400 font-sans">Master Admin</span>` : `
            <button
              type="button"
              id="role-btn-${u.id}"
              onclick="handleUpdateUserRole('${u.id}', document.getElementById('role-change-${u.id}').value)"
              class="px-3 py-1 text-xs font-semibold text-blue-700 bg-blue-50 hover:bg-blue-100 rounded-lg border border-blue-200 transition cursor-pointer flex items-center gap-1"
            >
              <i data-lucide="check" class="w-3 h-3"></i> Apply
            </button>
          `}
        </td>
      </tr>
    `;
  }).join('');

  if (window.lucide) lucide.createIcons();
}

function handleUserDirectorySearch(query) {
  const q = (query || '').toLowerCase().trim();
  if (!q) {
    renderUserDirectoryTable(_cachedAllUsers);
    return;
  }
  const filtered = _cachedAllUsers.filter(u => {
    return (
      (u.name && u.name.toLowerCase().includes(q)) ||
      (u.email && u.email.toLowerCase().includes(q)) ||
      (u.phone && u.phone.toLowerCase().includes(q)) ||
      (u.role && u.role.toLowerCase().includes(q)) ||
      (u.account_status && u.account_status.toLowerCase().includes(q)) ||
      (u.admin_auth_code && u.admin_auth_code.toLowerCase().includes(q))
    );
  });
  renderUserDirectoryTable(filtered);
}

/**
 * Toggle File Deletion Privilege for a User (Admin Only)
 */
async function handleToggleDeletePermission(userId, canDelete) {
  const token = getToken();
  if (!token) return;

  try {
    const res = await fetch('/api/auth/set-user-delete-permission', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ userId, canDelete }),
    });

    const data = await res.json();
    if (!res.ok) {
      showToast('Action Failed', data.error || 'Failed to update deletion privilege', 'error');
      return;
    }

    showToast('Permission Updated', data.message, 'success');
    loadAllUsers();
  } catch (err) {
    showToast('Error', err.message, 'error');
  }
}

/**
 * iOS-Style Logout Confirmation Modal
 */
function openLogoutModal() {
  const modal = document.getElementById('modal-logout-confirm');
  if (modal) {
    modal.classList.remove('hidden');
    modal.style.setProperty('display', 'flex', 'important');
  }
  if (window.lucide) lucide.createIcons();
}

function closeLogoutModal() {
  const modal = document.getElementById('modal-logout-confirm');
  if (modal) {
    modal.classList.add('hidden');
    modal.style.setProperty('display', 'none', 'important');
  }
}

function confirmLogout() {
  closeLogoutModal();
  clearSession();
}

window.handleApprovalsSearch = handleApprovalsSearch;
window.handleUserDirectorySearch = handleUserDirectorySearch;
window.handleToggleDeletePermission = handleToggleDeletePermission;
window.openLogoutModal = openLogoutModal;
window.closeLogoutModal = closeLogoutModal;
window.confirmLogout = confirmLogout;

/**
 * Administrator updates a user role
 */
async function handleUpdateUserRole(userId, newRole) {
  const token = getToken();
  if (!token) return;

  const btn = document.getElementById(`role-btn-${userId}`);
  const originalHtml = btn ? btn.innerHTML : 'Apply Role';
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = `<span class="inline-flex items-center gap-1"><svg class="animate-spin h-3 w-3 text-blue-600" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z"></path></svg> Updating...</span>`;
  }

  try {
    const res = await fetch('/api/auth/set-user-role', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ userId, role: newRole }),
    });

    const data = await res.json();
    if (!res.ok) {
      showToast('Update Failed', data.error || 'Failed to update user role', 'error');
      if (btn) {
        btn.disabled = false;
        btn.innerHTML = originalHtml;
      }
      return;
    }

    showToast('Role Updated', data.message || `User role updated to ${newRole}.`, 'success');
    loadAllUsers();
  } catch (err) {
    showToast('Error', err.message, 'error');
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = originalHtml;
    }
  }
}

window.generateNewAdminCode = generateNewAdminCode;
window.handleAdminDispatchCode = handleAdminDispatchCode;
window.handleUpdateUserRole = handleUpdateUserRole;

