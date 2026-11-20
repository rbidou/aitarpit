/* AI Tarpit Admin - Sessions */

let allSessions = [];

/**
 * Load the session list from the API and render it (applying the class filter).
 */
async function loadSessions() {
    const resp = await adminFetch('/api/admin/sessions?limit=500');
    if (!resp.status) {
        notify(resp.message || 'Failed to load sessions', 'error');
        return;
    }
    allSessions = resp.data.sessions;
    renderSessions();
}

/**
 * Render the sessions table from the current filter.
 */
function renderSessions() {
    const cls = document.getElementById('filter-class').value;
    const rows = allSessions.filter(s => !cls || s.classification === cls);
    const body = document.getElementById('sessions-body');
    if (!rows.length) {
        body.innerHTML = '<tr><td colspan="8" class="text-muted">No sessions</td></tr>';
        return;
    }
    body.innerHTML = rows.map(s => `<tr class="clickable" data-id="${escapeHtml(s.id)}">
        <td><span class="tech-id">${escapeHtml(s.id)}</span></td>
        <td>${escapeHtml(s.src_ip)}</td>
        <td><span class="tag ${CLASS_BADGE[s.classification] || 'badge-neutral'}">${escapeHtml(s.classification)}</span></td>
        <td>${Math.round(s.score)}</td>
        <td>${s.requests}</td>
        <td>${Math.round(s.held_seconds)}s</td>
        <td>${escapeHtml((s.techniques || []).join(', ') || '-')}</td>
        <td><button class="btn btn-sm copy-btn" data-value="${escapeHtml(s.id)}" title="Copy">&#9112;</button></td>
    </tr>`).join('');
    body.querySelectorAll('tr.clickable').forEach(tr =>
        tr.addEventListener('click', e => { if (!e.target.closest('.copy-btn')) loadDetail(tr.dataset.id); }));
    body.querySelectorAll('.copy-btn').forEach(btn =>
        btn.addEventListener('click', () => copyToClipboard(btn.dataset.value)));
}

/**
 * Load and render one session's detail.
 * @param {string} sid
 */
async function loadDetail(sid) {
    const resp = await adminFetch(`/api/admin/sessions/${encodeURIComponent(sid)}`);
    if (!resp.status) {
        notify(resp.message || 'Failed to load session', 'error');
        return;
    }
    const d = resp.data;
    document.getElementById('detail-panel').style.display = '';
    document.getElementById('detail-title').textContent = `Session ${sid}`;
    const data = d.session.data || {};
    const linked = (data.linked_sessions || []).join(', ');
    document.getElementById('detail-summary').innerHTML =
        `<span class="tag ${CLASS_BADGE[d.session.classification] || 'badge-neutral'}">${escapeHtml(d.session.classification)}</span> `
        + `score ${Math.round(d.session.score)} &middot; ${d.session.requests} requests &middot; `
        + `${Math.round(d.session.held_seconds)}s held &middot; UA: <code>${escapeHtml(d.session.user_agent || '')}</code>`
        + (linked ? ` &middot; linked: <code>${escapeHtml(linked)}</code>` : '');
    document.getElementById('detail-requests').innerHTML = d.requests.map(r => `<tr>
        <td class="text-muted">${escapeHtml(formatTs(r.ts))}</td><td>${escapeHtml(r.method)}</td>
        <td><code>${escapeHtml(r.path)}</code></td><td>${r.status}</td><td>${r.bytes_out}</td>
        <td><span class="tech-id">${escapeHtml(r.technique || '-')}</span></td></tr>`).join('')
        || '<tr><td colspan="6" class="text-muted">none</td></tr>';
    document.getElementById('detail-events').innerHTML = d.events.map(e => `<tr>
        <td class="text-muted">${escapeHtml(formatTs(e.ts))}</td>
        <td><span class="tag ${SEVERITY_BADGE[e.severity] || 'badge-neutral'}">${escapeHtml(e.severity)}</span></td>
        <td class="text-muted">${escapeHtml(e.type)}</td><td>${escapeHtml(e.message)}</td></tr>`).join('')
        || '<tr><td colspan="4" class="text-muted">none</td></tr>';
    document.getElementById('detail-submissions').textContent =
        d.submissions.length ? d.submissions.map(s => `[${s.technique}/${s.kind}] ${s.content}`).join('\n\n') : 'none';
    document.getElementById('detail-panel').scrollIntoView({ behavior: 'smooth' });
}

document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('refresh-btn').addEventListener('click', loadSessions);
    document.getElementById('filter-class').addEventListener('change', renderSessions);
    loadSessions();
});
