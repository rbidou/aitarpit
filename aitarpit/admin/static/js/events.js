/* AI Tarpit Admin - Events */

/**
 * Load events from the API using the current filters and render them.
 */
async function loadEvents() {
    const sev = document.getElementById('filter-severity').value;
    const tech = document.getElementById('filter-technique').value.trim();
    const sid = document.getElementById('filter-session').value.trim();
    const params = new URLSearchParams({ min_severity: sev, limit: '500' });
    if (sid) params.set('session_id', sid);
    const resp = await adminFetch(`/api/admin/events?${params.toString()}`);
    const body = document.getElementById('events-body');
    if (!resp.status) {
        body.innerHTML = `<tr><td colspan="7" style="color:var(--danger);">${escapeHtml(resp.message || 'Failed')}</td></tr>`;
        return;
    }
    const rows = resp.data.events.filter(e => !tech || (e.technique || '') === tech);
    if (!rows.length) {
        body.innerHTML = '<tr><td colspan="7" class="text-muted">No matching events</td></tr>';
        return;
    }
    body.innerHTML = rows.map(e => `<tr>
        <td class="text-muted">${escapeHtml(formatTs(e.ts))}</td>
        <td><span class="tag ${SEVERITY_BADGE[e.severity] || 'badge-neutral'}">${escapeHtml(e.severity)}</span></td>
        <td><span class="tech-id">${escapeHtml(e.technique || '-')}</span></td>
        <td class="text-muted">${escapeHtml(e.type)}</td>
        <td><span class="tech-id">${escapeHtml(e.session_id || '-')}</span></td>
        <td>${escapeHtml(e.message)}</td>
        <td><button class="btn btn-sm copy-btn" data-value="${escapeHtml(e.message)}" title="Copy">&#9112;</button></td>
    </tr>`).join('');
    body.querySelectorAll('.copy-btn').forEach(btn =>
        btn.addEventListener('click', () => copyToClipboard(btn.dataset.value)));
}

document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('apply-btn').addEventListener('click', loadEvents);
    ['filter-technique', 'filter-session'].forEach(id =>
        document.getElementById(id).addEventListener('keydown', e => { if (e.key === 'Enter') loadEvents(); }));
    document.getElementById('filter-severity').addEventListener('change', loadEvents);
    loadEvents();
});
