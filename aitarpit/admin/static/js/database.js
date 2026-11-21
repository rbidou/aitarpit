/* AI Tarpit Admin - Database
 *
 * Shows the store's size and per-element row counts, and deletes records of a
 * chosen type older than a cut-off (a number of days, or a specific date).
 */

/** Element types shown as counts, matching the server's DELETABLE_ELEMENTS keys. */
const DB_ELEMENTS = ['sessions', 'requests', 'events', 'submissions', 'honeytokens'];

/** Display label per element type. */
const ELEMENT_LABELS = {
    sessions: 'Sessions', requests: 'Requests', events: 'Events',
    submissions: 'Submissions', honeytokens: 'Honeytokens',
};

/**
 * Format a byte count as a short human-readable size.
 * @param {number} bytes
 * @returns {string}
 */
function formatBytes(bytes) {
    const n = Number(bytes) || 0;
    if (n < 1024) return `${n} B`;
    const units = ['KB', 'MB', 'GB', 'TB'];
    let value = n / 1024;
    let i = 0;
    while (value >= 1024 && i < units.length - 1) {
        value /= 1024;
        i += 1;
    }
    return `${value.toFixed(value >= 10 || i === 0 ? 0 : 1)} ${units[i]}`;
}

/**
 * Load the database metrics and render the size, counts and file path.
 */
async function loadMetrics() {
    const resp = await adminFetch('/api/admin/database');
    if (!resp.status) {
        notify(resp.message || 'Failed to load database metrics', 'error');
        return;
    }
    const data = resp.data || {};
    const counts = data.counts || {};
    document.getElementById('stat-size').textContent = formatBytes(data.size_bytes);
    DB_ELEMENTS.forEach(name => {
        document.getElementById(`stat-${name}`).textContent = (counts[name] || 0).toLocaleString();
    });
    const rows = DB_ELEMENTS.map(name =>
        `<tr><td>${ELEMENT_LABELS[name]}</td><td>${(counts[name] || 0).toLocaleString()}</td></tr>`).join('');
    const total = DB_ELEMENTS.reduce((sum, name) => sum + (counts[name] || 0), 0);
    document.getElementById('db-tablebody').innerHTML = rows +
        `<tr><td><strong>Total</strong></td><td><strong>${total.toLocaleString()}</strong></td></tr>`;
    const path = data.path && data.path !== ':memory:' ? data.path : 'in-memory database';
    document.getElementById('db-path').textContent =
        `File: ${path} · ${formatBytes(data.size_bytes)} · schema version ${data.schema_version}`;
}

/**
 * Confirm, delete every stored record and reload the metrics.
 */
async function handleReset() {
    if (!confirm('Reset the database?\n\nThis permanently deletes ALL stored sessions, requests, events, '
        + 'submissions and honeytokens. This cannot be undone.')) return;
    const resp = await adminFetch('/api/admin/database/reset', { method: 'POST' });
    if (!resp.status) {
        notify(resp.message || 'Reset failed', 'error');
        return;
    }
    notify('Database reset', 'success');
    loadMetrics();
}

/**
 * Show the days or date input according to the selected timeframe mode.
 */
function syncDeleteMode() {
    const mode = document.querySelector('input[name="del-mode"]:checked').value;
    document.getElementById('del-days-group').style.display = mode === 'days' ? '' : 'none';
    document.getElementById('del-date-group').style.display = mode === 'date' ? '' : 'none';
}

/**
 * Compute the delete cut-off (epoch seconds) from the active timeframe inputs.
 * @returns {?number} the cut-off, or null when the input is invalid
 */
function deleteCutoff() {
    const mode = document.querySelector('input[name="del-mode"]:checked').value;
    if (mode === 'days') {
        const days = parseInt(document.getElementById('del-days').value, 10);
        if (isNaN(days) || days < 0) return null;
        return Date.now() / 1000 - days * 86400;
    }
    const dateStr = document.getElementById('del-date').value;
    if (!dateStr) return null;
    const ms = Date.parse(`${dateStr}T00:00:00Z`);
    return isNaN(ms) ? null : ms / 1000;
}

/**
 * Validate the inputs, confirm, delete the selected records and reload metrics.
 */
async function handleDelete() {
    const element = document.getElementById('del-element').value;
    const label = document.getElementById('del-element').selectedOptions[0].textContent.trim();
    const cutoff = deleteCutoff();
    const result = document.getElementById('delete-result');
    if (cutoff === null) {
        result.innerHTML = '<span style="color:var(--danger);">Enter a valid number of days or a date.</span>';
        return;
    }
    const when = new Date(cutoff * 1000).toISOString().replace('T', ' ').slice(0, 19);
    if (!confirm(`Permanently delete ${element} older than ${when} UTC?\n\n(${label})`)) return;
    result.innerHTML = '';
    const resp = await adminFetch('/api/admin/database/delete',
        { method: 'POST', body: { element, cutoff } });
    if (!resp.status) {
        result.innerHTML = `<span style="color:var(--danger);">${escapeHtml(resp.message || 'Delete failed')}</span>`;
        return;
    }
    const deleted = resp.data.deleted || {};
    const detail = Object.entries(deleted).map(([k, v]) => `${v} ${k}`).join(', ');
    result.innerHTML = `<span style="color:var(--success);">${escapeHtml(resp.message)} ${escapeHtml(detail)}</span>`;
    notify('Records deleted', 'success');
    loadMetrics();
}

document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('refresh-btn').addEventListener('click', loadMetrics);
    document.getElementById('reset-btn').addEventListener('click', handleReset);
    document.getElementById('delete-btn').addEventListener('click', handleDelete);
    document.querySelectorAll('input[name="del-mode"]').forEach(el =>
        el.addEventListener('change', syncDeleteMode));
    syncDeleteMode();
    loadMetrics();
});
