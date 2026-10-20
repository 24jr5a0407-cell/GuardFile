// TrustVault Immutable Audit Trail Module

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
            <td colspan="7" class="py-8 text-center text-slate-400 font-sans">
              <i data-lucide="shield-alert" class="w-6 h-6 mx-auto mb-1 text-slate-300"></i>
              System-wide audit trail is restricted to Administrators & Document Owners.
            </td>
          </tr>
        `;
        lucide.createIcons();
        return;
      }
      tableBody.innerHTML = `<tr><td colspan="7" class="py-4 text-center text-rose-500">Failed to load audit logs.</td></tr>`;
      return;
    }

    const data = await res.json();
    const logs = data.logs || [];

    if (logs.length === 0) {
      tableBody.innerHTML = `<tr><td colspan="7" class="py-8 text-center text-slate-400 font-sans">No audit events match filters.</td></tr>`;
      return;
    }

    const actionBadges = {
      UPLOAD: 'bg-blue-100 text-blue-800 border-blue-200',
      READ_SUCCESS: 'bg-emerald-100 text-emerald-800 border-emerald-200',
      READ_DENIED: 'bg-rose-100 text-rose-800 border-rose-200 font-bold',
      GRANT: 'bg-purple-100 text-purple-800 border-purple-200',
      REVOKE: 'bg-amber-100 text-amber-800 border-amber-200 font-bold',
      DELETE: 'bg-slate-200 text-slate-800 border-slate-300',
      AUTH_LOGIN_SUCCESS: 'bg-emerald-50 text-emerald-700 border-emerald-200',
      AUTH_LOGIN_FAILED: 'bg-rose-50 text-rose-700 border-rose-200',
    };

    tableBody.innerHTML = logs.map(l => {
      const shortPrev = `${l.prev_hash.substring(0, 6)}..`;
      const shortEntry = `${l.entry_hash.substring(0, 6)}..`;
      const formattedTime = new Date(l.timestamp).toLocaleTimeString('en-US', { hour12: false }) + '.' + new Date(l.timestamp).getMilliseconds();

      return `
        <tr class="hover:bg-slate-50 transition ${l.status === 'DENIED' ? 'bg-rose-50/30' : ''}">
          <td class="py-2.5 px-4 whitespace-nowrap text-slate-500 font-mono text-[11px]">${formattedTime}</td>
          <td class="py-2.5 px-4 whitespace-nowrap">
            <span class="px-2 py-0.5 rounded text-[10px] font-bold border ${actionBadges[l.action] || 'bg-slate-100'}">
              ${l.action}
            </span>
          </td>
          <td class="py-2.5 px-4 whitespace-nowrap font-sans text-xs text-slate-800 font-medium">${l.actor_email || 'anonymous'}</td>
          <td class="py-2.5 px-4 whitespace-nowrap font-mono text-slate-600 text-[11px]">${l.target_resource}</td>
          <td class="py-2.5 px-4 whitespace-nowrap font-mono text-slate-500 text-[11px]">${l.ip_address}</td>
          <td class="py-2.5 px-4 whitespace-nowrap">
            <span class="px-2 py-0.5 rounded-full text-[10px] font-bold ${l.status === 'SUCCESS' ? 'bg-emerald-100 text-emerald-800' : 'bg-rose-100 text-rose-800'}">
              ${l.status}
            </span>
          </td>
          <td class="py-2.5 px-4 whitespace-nowrap font-mono text-[10px] text-slate-400" title="Prev: ${l.prev_hash}\nEntry: ${l.entry_hash}">
            <span class="text-slate-400">${shortPrev}</span> &rarr; <span class="text-blue-600 font-bold">${shortEntry}</span>
          </td>
        </tr>
      `;
    }).join('');

    lucide.createIcons();
  } catch (err) {
    tableBody.innerHTML = `<tr><td colspan="7" class="py-4 text-center text-rose-500">${err.message}</td></tr>`;
  }
}

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
