// GuardFile Immutable Audit Trail Module

let _cachedAuditLogs = [];

/**
 * Loads immutable audit logs from server.
 */
async function loadAuditLogs() {
  const tableBody = document.getElementById('audit-table-body');
  if (!tableBody) return;

  const token = getToken();
  if (!token) return;

  const status = document.getElementById('audit-filter-status')?.value || '';
  const action = document.getElementById('audit-filter-action')?.value || '';

  try {
    const url = new URL('/api/audit', window.location.origin);
    if (status) url.searchParams.append('status', status);
    if (action) url.searchParams.append('action', action);

    const res = await fetch(url, {
      headers: { Authorization: `Bearer ${token}` },
    });

    if (!res.ok) {
      if (res.status === 403) {
        tableBody.innerHTML = `
          <tr>
            <td colspan="7" class="py-12 text-center text-slate-400 font-sans">
              <i data-lucide="shield-alert" class="w-8 h-8 mx-auto mb-2 text-slate-300"></i>
              System-wide audit trail is restricted to Administrators & Document Owners.
            </td>
          </tr>
        `;
        if (window.lucide) lucide.createIcons();
        return;
      }
      tableBody.innerHTML = `<tr><td colspan="7" class="py-6 text-center text-rose-500 font-sans">Failed to load audit logs.</td></tr>`;
      return;
    }

    const data = await res.json();
    _cachedAuditLogs = data.logs || [];
    renderAuditTable(_cachedAuditLogs);
  } catch (err) {
    tableBody.innerHTML = `<tr><td colspan="7" class="py-6 text-center text-rose-500 font-sans">${err.message}</td></tr>`;
  }
}

/**
 * Renders audit log rows
 */
function renderAuditTable(logs) {
  const tableBody = document.getElementById('audit-table-body');
  if (!tableBody) return;

  if (logs.length === 0) {
    tableBody.innerHTML = `<tr><td colspan="7" class="py-12 text-center text-slate-400 font-sans">No audit events match filters.</td></tr>`;
    return;
  }

  const actionBadges = {
    UPLOAD: 'bg-blue-100 text-blue-800 border-blue-200',
    IMPORT: 'bg-purple-100 text-purple-800 border-purple-200',
    READ_SUCCESS: 'bg-emerald-100 text-emerald-800 border-emerald-200',
    READ_DENIED: 'bg-rose-100 text-rose-800 border-rose-200 font-bold',
    GRANT: 'bg-purple-100 text-purple-800 border-purple-200',
    REVOKE: 'bg-amber-100 text-amber-800 border-amber-200 font-bold',
    DELETE: 'bg-slate-200 text-slate-800 border-slate-300',
    DELETE_DENIED: 'bg-rose-100 text-rose-800 border-rose-200 font-bold',
    DOWNLOAD_DENIED: 'bg-rose-100 text-rose-800 border-rose-200 font-bold',
    AUTH_LOGIN_SUCCESS: 'bg-emerald-50 text-emerald-700 border-emerald-200',
    AUTH_LOGIN_FAILED: 'bg-rose-50 text-rose-700 border-rose-200',
    ADMIN_DISPATCHED_CODE: 'bg-purple-50 text-purple-700 border-purple-200',
    ADMIN_UPDATED_DELETION_PRIVILEGE: 'bg-indigo-50 text-indigo-700 border-indigo-200',
  };

  tableBody.innerHTML = logs.map(l => {
    const shortPrev = l.prev_hash ? `${l.prev_hash.substring(0, 6)}..` : '000000..';
    const shortEntry = l.entry_hash ? `${l.entry_hash.substring(0, 6)}..` : '-';
    const formattedTime = new Date(l.timestamp).toLocaleTimeString('en-US', { hour12: false }) + '.' + new Date(l.timestamp).getMilliseconds();

    return `
      <tr class="hover:bg-slate-50/80 transition ${l.status === 'DENIED' ? 'bg-rose-50/40' : ''}">
        <td class="py-3 px-4 whitespace-nowrap text-slate-500 font-mono text-[11px]">${formattedTime}</td>
        <td class="py-3 px-4 whitespace-nowrap">
          <span class="px-2 py-0.5 rounded text-[10px] font-bold border ${actionBadges[l.action] || 'bg-slate-100 text-slate-700'}">
            ${l.action}
          </span>
        </td>
        <td class="py-3 px-4 whitespace-nowrap font-sans text-xs text-slate-800 font-medium">${l.actor_email || 'anonymous'}</td>
        <td class="py-3 px-4 whitespace-nowrap font-mono text-slate-600 text-[11px]">${l.target_resource}</td>
        <td class="py-3 px-4 whitespace-nowrap font-mono text-slate-500 text-[11px]">${l.ip_address}</td>
        <td class="py-3 px-4 whitespace-nowrap">
          <span class="px-2 py-0.5 rounded-full text-[10px] font-bold ${l.status === 'SUCCESS' ? 'bg-emerald-100 text-emerald-800' : 'bg-rose-100 text-rose-800'}">
            ${l.status}
          </span>
        </td>
        <td class="py-3 px-4 whitespace-nowrap font-mono text-[10px] text-slate-400" title="Prev: ${l.prev_hash}\nEntry: ${l.entry_hash}">
          <span class="text-slate-400">${shortPrev}</span> &rarr; <span class="text-blue-600 font-bold">${shortEntry}</span>
        </td>
      </tr>
    `;
  }).join('');

  if (window.lucide) lucide.createIcons();
}

/**
 * Real-time filter search for audit ledger
 */
function handleAuditSearch(query) {
  const q = (query || '').toLowerCase().trim();
  if (!q) {
    renderAuditTable(_cachedAuditLogs);
    return;
  }

  const filtered = _cachedAuditLogs.filter(l => {
    return (
      (l.action && l.action.toLowerCase().includes(q)) ||
      (l.actor_email && l.actor_email.toLowerCase().includes(q)) ||
      (l.target_resource && l.target_resource.toLowerCase().includes(q)) ||
      (l.ip_address && l.ip_address.toLowerCase().includes(q)) ||
      (l.status && l.status.toLowerCase().includes(q)) ||
      (l.entry_hash && l.entry_hash.toLowerCase().includes(q))
    );
  });

  renderAuditTable(filtered);
}

window.handleAuditSearch = handleAuditSearch;

/**
 * Triggers cryptographic hash chain verification.
 */
async function verifyCryptographicChain() {
  const token = getToken();
  try {
    const res = await fetch('/api/audit/verify', {
      headers: { Authorization: `Bearer ${token}` },
    });

    const data = await res.json();

    if (data.valid) {
      showToast(
        'Ledger Integrity 100% Proven',
        `Verified ${data.totalRecords} chained blocks. Head SHA-256: ${data.headHash.substring(0, 16)}...`,
        'success'
      );
    } else {
      showToast(
        'Integrity Violation Detected!',
        `Ledger alteration at block ${data.errorIndex}! Reason: ${data.reason}`,
        'error'
      );
    }
  } catch (err) {
    showToast('Verification Error', err.message, 'error');
  }
}
