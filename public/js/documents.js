// TrustVault Secured Documents Module

let activeDocs = [];
let currentPermDocId = null;

/**
 * Loads documents visible to the current authenticated user.
 */
async function loadDocuments() {
  const grid = document.getElementById('documents-grid');
  const token = getToken();

  if (!token) {
    grid.innerHTML = `
      <div class="col-span-full py-16 text-center text-slate-400">
        <i data-lucide="lock" class="w-10 h-10 mx-auto mb-3 text-slate-300"></i>
        <p class="text-sm font-semibold">Please sign in to view secured documents.</p>
      </div>
    `;
    lucide.createIcons();
    return;
  }

  const queryParam = document.getElementById('search-input')?.value || '';
  const categoryParam = document.getElementById('filter-category')?.value || '';

  try {
    const url = new URL('/api/documents', window.location.origin);
    if (queryParam) url.searchParams.append('q', queryParam);
    if (categoryParam) url.searchParams.append('category', categoryParam);

    const res = await fetch(url, {
      headers: { Authorization: `Bearer ${token}` },
    });

    if (!res.ok) {
      grid.innerHTML = `
        <div class="col-span-full py-12 text-center text-rose-500 text-sm">
          Failed to load documents. (${res.status} ${res.statusText})
        </div>
      `;
      return;
    }

    const data = await res.json();
    activeDocs = data.documents || [];
    renderDocuments(activeDocs);
  } catch (err) {
    grid.innerHTML = `<div class="col-span-full py-12 text-center text-rose-500 text-sm">${err.message}</div>`;
  }
}

/**
 * Renders the document cards in the grid.
 */
function renderDocuments(docs) {
  const grid = document.getElementById('documents-grid');
  if (!grid) return;

  if (docs.length === 0) {
    grid.innerHTML = `
      <div class="col-span-full py-16 text-center bg-white rounded-2xl border border-slate-200">
        <div class="w-12 h-12 rounded-2xl bg-slate-50 flex items-center justify-center mx-auto mb-3 text-slate-400">
          <i data-lucide="file-question" class="w-6 h-6"></i>
        </div>
        <h4 class="text-sm font-bold text-slate-700">No Secured Documents Found</h4>
        <p class="text-xs text-slate-400 mt-1">You only see files you own or have an active, unrevoked grant for.</p>
      </div>
    `;
    lucide.createIcons();
    return;
  }

  grid.innerHTML = docs.map(doc => {
    const isOwner = doc.user_access_level === 'owner';
    const isAdmin = currentUser?.role === 'admin';
    const canManage = isOwner || isAdmin;

    const categoryBadges = {
      'HR / Payroll': 'bg-purple-50 text-purple-700 border-purple-200',
      'Engineering': 'bg-blue-50 text-blue-700 border-blue-200',
      'Finance': 'bg-emerald-50 text-emerald-700 border-emerald-200',
      'Legal': 'bg-amber-50 text-amber-700 border-amber-200',
    };

    const formattedDate = new Date(doc.created_at).toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
    });

    const formattedSize = (doc.file_size / 1024).toFixed(1) + ' KB';
    const shortHash = doc.file_hash ? `${doc.file_hash.substring(0, 8)}...${doc.file_hash.substring(56)}` : '-';

    return `
      <div class="bg-white rounded-2xl border border-slate-200 p-5 shadow-xs hover:shadow-md transition flex flex-col justify-between gap-4">
        <div>
          <!-- Card Header & Category Badge -->
          <div class="flex items-start justify-between gap-2 mb-3">
            <span class="text-[10px] font-bold uppercase px-2.5 py-0.5 rounded-full border ${categoryBadges[doc.category] || 'bg-slate-100 text-slate-700'}">
              ${doc.category}
            </span>
            <span class="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-100 text-slate-500" title="Full SHA-256: ${doc.file_hash}">
              #${shortHash}
            </span>
          </div>

          <!-- Document Title & Filename -->
          <h3 class="text-sm font-bold text-slate-900 mb-1 leading-snug hover:text-blue-600 transition">
            ${doc.title}
          </h3>
          <p class="text-xs text-slate-500 font-mono flex items-center gap-1">
            <i data-lucide="paperclip" class="w-3 h-3 text-slate-400"></i> ${doc.file_name} (${formattedSize})
          </p>

          <!-- Owner & Date Metadata -->
          <div class="mt-4 pt-3 border-t border-slate-100 flex items-center justify-between text-[11px] text-slate-500">
            <div class="flex items-center gap-1.5">
              <i data-lucide="user" class="w-3.5 h-3.5 text-slate-400"></i>
              <span>${doc.owner_name || doc.owner_email}</span>
            </div>
            <span>${formattedDate}</span>
          </div>
        </div>

        <!-- Action Buttons -->
        <div class="pt-3 border-t border-slate-100 flex items-center justify-between gap-2">
          <div class="flex items-center gap-1.5">
            <button onclick="previewDocument('${doc.id}', '${doc.title}')" class="px-2.5 py-1.5 text-xs font-semibold text-slate-700 bg-slate-100 hover:bg-slate-200 rounded-lg flex items-center gap-1 transition">
              <i data-lucide="eye" class="w-3.5 h-3.5"></i> Preview
            </button>
            <button onclick="downloadDocument('${doc.id}', '${doc.file_name}')" class="px-2.5 py-1.5 text-xs font-semibold text-blue-700 bg-blue-50 hover:bg-blue-100 rounded-lg flex items-center gap-1 transition">
              <i data-lucide="download" class="w-3.5 h-3.5"></i> Stream
            </button>
          </div>

          <div class="flex items-center gap-1">
            ${canManage ? `
              <button onclick="openPermissionsModal('${doc.id}', '${doc.title}')" class="p-1.5 text-slate-500 hover:text-blue-600 hover:bg-blue-50 rounded-lg transition" title="Manage Permissions & Instant Revoke">
                <i data-lucide="shield-check" class="w-4 h-4"></i>
              </button>
              <button onclick="deleteDocument('${doc.id}', '${doc.title}')" class="p-1.5 text-slate-400 hover:text-rose-600 hover:bg-rose-50 rounded-lg transition" title="Delete Document">
                <i data-lucide="trash-2" class="w-4 h-4"></i>
              </button>
            ` : `
              <span class="text-[10px] font-semibold text-slate-400 px-2 py-0.5 rounded bg-slate-50 uppercase">
                ${doc.user_access_level}
              </span>
            `}
          </div>
        </div>
      </div>
    `;
  }).join('');

  lucide.createIcons();
}

function handleSearch() {
  loadDocuments();
}

/**
 * Downloads a document securely via server streaming.
 */
async function downloadDocument(docId, fileName) {
  const token = getToken();
  try {
    const res = await fetch(`/api/documents/${docId}/download`, {
      headers: { Authorization: `Bearer ${token}` },
    });

    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      showToast('Access Blocked (Zero-Trust)', errData.message || 'Permission denied.', 'error');
      // Refresh audit logs to show the recorded READ_DENIED attempt
      if (typeof loadAuditLogs === 'function') loadAuditLogs();
      if (typeof updateStats === 'function') updateStats();
      return;
    }

    const blob = await res.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = fileName;
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.URL.revokeObjectURL(url);

    showToast('Download Verified', `Securely streamed ${fileName}`, 'success');
    if (typeof loadAuditLogs === 'function') loadAuditLogs();
    if (typeof updateStats === 'function') updateStats();
  } catch (err) {
    showToast('Stream Error', err.message, 'error');
  }
}

/**
 * Previews document inline in modal.
 */
async function previewDocument(docId, title) {
  const token = getToken();
  const previewModal = document.getElementById('modal-preview');
  const container = document.getElementById('preview-container');
  document.getElementById('preview-modal-title').textContent = title;

  container.innerHTML = '<div class="text-slate-400 text-xs flex items-center gap-2"><i data-lucide="loader" class="w-4 h-4 animate-spin"></i> Authorizing stream...</div>';
  previewModal.classList.remove('hidden');
  lucide.createIcons();

  try {
    const res = await fetch(`/api/documents/${docId}/preview`, {
      headers: { Authorization: `Bearer ${token}` },
    });

    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      container.innerHTML = `
        <div class="text-center p-8 bg-rose-50 border border-rose-200 rounded-xl max-w-md">
          <i data-lucide="shield-x" class="w-10 h-10 text-rose-500 mx-auto mb-2"></i>
          <h4 class="text-sm font-bold text-rose-800">403 Forbidden: Zero-Trust Interception</h4>
          <p class="text-xs text-rose-600 mt-1">${errData.message || 'You lack an active unrevoked grant for this resource.'}</p>
          <p class="text-[11px] text-slate-500 mt-3 font-mono">Attempt permanently recorded in audit ledger.</p>
        </div>
      `;
      lucide.createIcons();
      if (typeof loadAuditLogs === 'function') loadAuditLogs();
      if (typeof updateStats === 'function') updateStats();
      return;
    }

    const blob = await res.blob();
    const blobUrl = window.URL.createObjectURL(blob);

    if (blob.type.includes('pdf')) {
      container.innerHTML = `<iframe src="${blobUrl}" class="w-full h-full rounded-xl border border-slate-200"></iframe>`;
    } else if (blob.type.includes('image')) {
      container.innerHTML = `<img src="${blobUrl}" class="max-h-full max-w-full rounded-xl object-contain mx-auto" />`;
    } else {
      const text = await blob.text();
      container.innerHTML = `<pre class="w-full h-full bg-white p-4 font-mono text-xs text-slate-800 rounded-xl border border-slate-200 overflow-auto whitespace-pre-wrap">${text}</pre>`;
    }
    if (typeof loadAuditLogs === 'function') loadAuditLogs();
    if (typeof updateStats === 'function') updateStats();
  } catch (err) {
    container.innerHTML = `<div class="text-rose-500 text-xs">${err.message}</div>`;
  }
}

function closePreviewModal() {
  document.getElementById('modal-preview')?.classList.add('hidden');
}

/**
 * Permissions Management Modal (Grant access & Instant Revoke)
 */
async function openPermissionsModal(docId, title) {
  currentPermDocId = docId;
  document.getElementById('perm-modal-doc-title').textContent = `Document: ${title}`;
  document.getElementById('modal-permissions')?.classList.remove('hidden');

  // Load all system users into the grant dropdown
  await loadUserDirectory();
  // Load current grants roster
  await loadDocumentPermissions(docId);
}

function closePermissionsModal() {
  document.getElementById('modal-permissions')?.classList.add('hidden');
  currentPermDocId = null;
}

async function loadUserDirectory() {
  const select = document.getElementById('grant-user-select');
  const token = getToken();

  try {
    const res = await fetch('/api/auth/users', {
      headers: { Authorization: `Bearer ${token}` },
    });
    const data = await res.json();
    const users = (data.users || []).filter(u => u.id !== currentUser?.id);

    select.innerHTML = '<option value="">Select recipient user...</option>' +
      users.map(u => `<option value="${u.id}">${u.name} (${u.email}) - ${u.role.toUpperCase()}</option>`).join('');
  } catch (err) {
    console.error('Failed to load user directory:', err);
  }
}

async function loadDocumentPermissions(docId) {
  const listEl = document.getElementById('permissions-roster-list');
  const token = getToken();

  try {
    const res = await fetch(`/api/permissions/document/${docId}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    const data = await res.json();
    const perms = data.permissions || [];

    if (perms.length === 0) {
      listEl.innerHTML = '<p class="text-xs text-slate-400 py-3 text-center">No explicit permissions granted yet.</p>';
      return;
    }

    listEl.innerHTML = perms.map(p => `
      <div class="p-2.5 rounded-xl border ${p.is_revoked ? 'bg-slate-50 border-slate-200 opacity-60' : 'bg-white border-slate-200'} flex items-center justify-between gap-3 text-xs">
        <div>
          <div class="flex items-center gap-2">
            <span class="font-bold text-slate-900">${p.user_name}</span>
            <span class="text-[10px] font-mono text-slate-500">${p.user_email}</span>
            <span class="text-[10px] uppercase font-bold px-1.5 py-0.2 rounded ${p.access_level === 'edit' ? 'bg-amber-100 text-amber-800' : 'bg-blue-100 text-blue-800'}">
              ${p.access_level}
            </span>
          </div>
          <p class="text-[11px] text-slate-400 mt-0.5">
            ${p.is_revoked ? `<span class="text-amber-600 font-semibold">REVOKED</span> on ${new Date(p.revoked_at).toLocaleTimeString()}` : `Active since ${new Date(p.granted_at).toLocaleTimeString()}`}
          </p>
        </div>

        <div>
          ${!p.is_revoked ? `
            <button onclick="handleRevokeClick('${docId}', '${p.user_id}')" class="px-2.5 py-1 text-[11px] font-bold text-amber-700 bg-amber-50 hover:bg-amber-100 border border-amber-200 rounded-lg transition">
              Revoke Access
            </button>
          ` : `
            <span class="text-[11px] text-slate-400 italic">Access Terminated</span>
          `}
        </div>
      </div>
    `).join('');
  } catch (err) {
    listEl.innerHTML = `<p class="text-xs text-rose-500">${err.message}</p>`;
  }
}

async function handleGrantSubmit(e) {
  e.preventDefault();
  if (!currentPermDocId) return;

  const userId = document.getElementById('grant-user-select').value;
  const accessLevel = document.getElementById('grant-level-select').value;
  const token = getToken();

  if (!userId) return;

  try {
    const res = await fetch('/api/permissions/grant', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ documentId: currentPermDocId, userId, accessLevel }),
    });

    const data = await res.json();
    if (!res.ok) {
      showToast('Grant Failed', data.error || 'Unable to grant access.', 'error');
      return;
    }

    showToast('Permission Granted', data.message, 'success');
    await loadDocumentPermissions(currentPermDocId);
    if (typeof loadAuditLogs === 'function') loadAuditLogs();
    if (typeof updateStats === 'function') updateStats();
  } catch (err) {
    showToast('Grant Error', err.message, 'error');
  }
}

async function handleRevokeClick(docId, userId) {
  const token = getToken();

  try {
    const res = await fetch('/api/permissions/revoke', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ documentId: docId, userId, reason: 'Manual revocation by owner' }),
    });

    const data = await res.json();
    if (!res.ok) {
      showToast('Revoke Failed', data.error || 'Unable to revoke.', 'error');
      return;
    }

    showToast('Access Immediately Revoked', data.message, 'success');
    await loadDocumentPermissions(docId);
    if (typeof loadAuditLogs === 'function') loadAuditLogs();
    if (typeof updateStats === 'function') updateStats();
  } catch (err) {
    showToast('Revocation Error', err.message, 'error');
  }
}

async function deleteDocument(docId, title) {
  if (!confirm(`Are you sure you want to permanently destroy "${title}" and all its records?`)) return;

  const token = getToken();
  try {
    const res = await fetch(`/api/documents/${docId}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${token}` },
    });

    const data = await res.json();
    if (!res.ok) {
      showToast('Delete Failed', data.error, 'error');
      return;
    }

    showToast('Document Destroyed', `Permanently deleted "${title}".`, 'success');
    loadDocuments();
    if (typeof loadAuditLogs === 'function') loadAuditLogs();
    if (typeof updateStats === 'function') updateStats();
  } catch (err) {
    showToast('Delete Error', err.message, 'error');
  }
}

function openUploadModal() {
  document.getElementById('modal-upload')?.classList.remove('hidden');
  document.getElementById('upload-error')?.classList.add('hidden');
}

function closeUploadModal() {
  document.getElementById('modal-upload')?.classList.add('hidden');
  document.getElementById('upload-form')?.reset();
}

async function handleUploadSubmit(e) {
  e.preventDefault();
  const token = getToken();
  const title = document.getElementById('upload-title').value;
  const category = document.getElementById('upload-category').value;
  const fileInput = document.getElementById('upload-file');
  const errorEl = document.getElementById('upload-error');
  const submitBtn = document.getElementById('btn-submit-upload');

  if (!fileInput.files || fileInput.files.length === 0) {
    errorEl.textContent = 'Please choose a file.';
    errorEl.classList.remove('hidden');
    return;
  }

  const file = fileInput.files[0];
  const formData = new FormData();
  formData.append('title', title);
  formData.append('category', category);
  formData.append('file', file);

  errorEl.classList.add('hidden');
  submitBtn.disabled = true;
  submitBtn.innerHTML = '<i data-lucide="loader" class="w-4 h-4 animate-spin"></i> Validating & Sealing...';
  lucide.createIcons();

  try {
    const res = await fetch('/api/documents/upload', {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
      body: formData,
    });

    const data = await res.json();

    if (!res.ok) {
      errorEl.textContent = data.reason || data.error || 'Upload rejected.';
      errorEl.classList.remove('hidden');
      submitBtn.disabled = false;
      submitBtn.innerHTML = '<i data-lucide="shield" class="w-4 h-4"></i> Seal & Upload';
      lucide.createIcons();
      return;
    }

    closeUploadModal();
    showToast('Document Secured', `Uploaded & cryptographically sealed: ${title}`, 'success');
    loadDocuments();
    if (typeof loadAuditLogs === 'function') loadAuditLogs();
    if (typeof updateStats === 'function') updateStats();
  } catch (err) {
    errorEl.textContent = err.message;
    errorEl.classList.remove('hidden');
    submitBtn.disabled = false;
    submitBtn.innerHTML = '<i data-lucide="shield" class="w-4 h-4"></i> Seal & Upload';
    lucide.createIcons();
  }
}
