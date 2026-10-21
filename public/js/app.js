// GuardFile Main Application Controller

function switchTab(tabName) {
  console.log('[Tabs] Switching to tab:', tabName);

  // Hide all tab views with both class and !important inline style
  document.querySelectorAll('.tab-view').forEach(view => {
    view.classList.add('hidden');
    view.style.setProperty('display', 'none', 'important');
  });

  // Reset all tab button styles
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.classList.remove('active', 'bg-blue-50', 'text-blue-700', 'border-blue-200');
    btn.classList.add('text-slate-600');
  });

  // Activate target view
  const targetView = document.getElementById(`view-${tabName}`);
  const targetBtn = document.getElementById(`tab-btn-${tabName}`);

  if (targetView) {
    targetView.classList.remove('hidden');
    targetView.style.setProperty('display', 'flex', 'important');
  }

  if (targetBtn) {
    targetBtn.classList.remove('text-slate-600');
    targetBtn.classList.add('active', 'bg-blue-50', 'text-blue-700', 'border-blue-200');
  }

  try {
    if (typeof lucide !== 'undefined' && lucide && typeof lucide.createIcons === 'function') {
      lucide.createIcons();
    }
  } catch (e) {}

  // Trigger data loaders in safe try-catch blocks
  try {
    if (tabName === 'documents' && typeof loadDocuments === 'function') {
      loadDocuments();
    } else if (tabName === 'audit' && typeof loadAuditLogs === 'function') {
      loadAuditLogs();
    } else if (tabName === 'approvals') {
      if (typeof loadPendingApprovals === 'function') {
        loadPendingApprovals();
      }
      if (typeof loadAllUsers === 'function') {
        loadAllUsers();
      }
    }
  } catch (err) {
    console.error('[Tabs] Error loading data for tab', tabName, err);
  }
}

// Explicitly register on window
window.switchTab = switchTab;

/**
 * Updates top metrics statistics.
 */
async function updateStats() {
  const token = getToken();
  if (!token) return;

  try {
    const res = await fetch('/api/audit/stats', {
      headers: { Authorization: `Bearer ${token}` },
    });

    if (!res.ok) return;

    const data = await res.json();
    document.getElementById('stat-total-docs').textContent = data.totalDocuments ?? 0;
    document.getElementById('stat-active-grants').textContent = data.activePermissions ?? 0;
    document.getElementById('stat-revoked-grants').textContent = data.revokedPermissions ?? 0;
    document.getElementById('stat-denied-attempts').textContent = data.deniedAccessAttempts ?? 0;
  } catch (err) {
    console.error('Failed to update stats:', err);
  }
}

/**
 * Displays an interactive toast notification.
 */
function showToast(title, message, type = 'info') {
  if (typeof window.showToast === 'function' && window.showToast !== showToast) {
    return window.showToast(title, message, type);
  }

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

// Initial application boot
document.addEventListener('DOMContentLoaded', async () => {
  await initAuth();
  await updateStats();
});
