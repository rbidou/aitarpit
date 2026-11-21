/* AI Tarpit Admin - Dashboard */

const REFRESH_MS = 5000;

/**
 * Fetch status + recent events and repaint the dashboard.
 */
async function refresh() {
    const [status, events] = await Promise.all([
        adminFetch('/api/admin/status'),
        adminFetch('/api/admin/events?limit=25'),
    ]);
    if (status.status) renderStatus(status.data);
    if (events.status) renderEvents(events.data.events);
}

/**
 * Paint the stat cards and persona line.
 * @param {object} data - status payload
 */
function renderStatus(data) {
    const s = data.stats;
    document.getElementById('stat-sessions').textContent = s.sessions;
    document.getElementById('stat-active').textContent = data.active_sessions;
    document.getElementById('stat-requests').textContent = s.requests;
    document.getElementById('stat-held').textContent = `${Math.round(s.held_seconds)}s`;
    document.getElementById('stat-tokens').textContent = Math.round(s.bytes_out / 4).toLocaleString();
    document.getElementById('stat-critical').textContent = s.events_by_severity.critical || 0;
    const p = data.persona;
    document.getElementById('persona-line').textContent =
        `${p.company} (${p.domain}) - ${p.employees} staff, ${p.services.length} services, ${data.techniques.filter(t => t.enabled).length} techniques enabled`;
}

/**
 * Paint the recent-events table.
 * @param {Array<object>} events
 */
function renderEvents(events) {
    const body = document.getElementById('events-body');
    if (!events.length) {
        body.innerHTML = '<tr><td colspan="5" class="text-muted">No events yet</td></tr>';
        return;
    }
    body.innerHTML = events.map(e => `<tr>
        <td class="text-muted">${escapeHtml(formatTs(e.ts))}</td>
        <td><span class="tag ${SEVERITY_BADGE[e.severity] || 'badge-neutral'}">${escapeHtml((e.severity || '').toUpperCase())}</span></td>
        <td><span class="tech-id">${escapeHtml(e.technique || '-')}</span></td>
        <td class="text-muted">${escapeHtml(e.type)}</td>
        <td>${escapeHtml(e.message)}</td>
    </tr>`).join('');
}

document.addEventListener('DOMContentLoaded', () => {
    refresh();
    setInterval(refresh, REFRESH_MS);
});
