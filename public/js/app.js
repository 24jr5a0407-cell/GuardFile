// TrustVault Main Application Controller

function switchTab(tabName) {
  // Hide all tab views
  document.querySelectorAll('.tab-view').forEach(view => view.classList.add('hidden'));
  document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active', 'bg-blue-50', 'text-blue-700', 'border-blue-200'));

  // Show active view
  const targetView = document.getElementById(`view-${tabName}`);
  const targetBtn = document.getElementById(`tab-btn-${tabName}`);

  if (targetView) targetView.classList.remove('hidden');
  if (targetBtn) targetBtn.classList.add('active', 'bg-blue-50', 'text-blue-700', 'border-blue-200');

  if (tabName === 'documents') {
    loadDocuments();
  } else if (tabName === 'audit') {
    loadAuditLogs();
  } else if (tabName === 'approvals') {
    loadPendingApprovals();
    if (typeof loadAllUsers === 'function') {
      loadAllUsers();
    }
  }
}

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
