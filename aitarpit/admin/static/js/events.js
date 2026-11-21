/* AI Tarpit Admin - Events */

/** Events matching the current filters, across all pages. */
let eventRows = [];
/** Current 1-based page number. */
let currentPage = 1;

/**
 * Load events from the API using the current filters, then render page 1.
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
        eventRows = [];
        body.innerHTML = `<tr><td colspan="6" style="color:var(--danger);">${escapeHtml(resp.message || 'Failed')}</td></tr>`;
        renderPagination();
        return;
    }
    eventRows = resp.data.events.filter(e => !tech || (e.technique || '') === tech);
    currentPage = 1;
    renderPage();
}

/**
 * Render the slice of events for the current page plus the pagination controls.
 */
function renderPage() {
    const body = document.getElementById('events-body');
    if (!eventRows.length) {
        body.innerHTML = '<tr><td colspan="6" class="text-muted">No matching events</td></tr>';
        renderPagination();
        return;
    }
    const perPage = parseInt(document.getElementById('per-page').value, 10);
    const start = (currentPage - 1) * perPage;
    const pageRows = eventRows.slice(start, start + perPage);
    body.innerHTML = pageRows.map(e => `<tr>
        <td class="text-muted">${escapeHtml(formatTs(e.ts))}</td>
        <td><span class="tag ${SEVERITY_BADGE[e.severity] || 'badge-neutral'}">${escapeHtml((e.severity || '').toUpperCase())}</span></td>
        <td>${techniqueCell(e.technique)}</td>
        <td class="text-muted">${escapeHtml(e.type)}</td>
        <td>${sessionCell(e.session_id)}</td>
        <td class="msg-cell">${escapeHtml(e.message)}</td>
    </tr>`).join('');
    body.querySelectorAll('.filter-value').forEach(el =>
        el.addEventListener('click', () => filterByValue(el.dataset.filter, el.dataset.value)));
    renderPagination();
}

/**
 * Render a clickable technique identifier cell, or a plain dash when absent.
 * @param {string} technique
 * @returns {string}
 */
function techniqueCell(technique) {
    if (!technique) return '<span class="tech-id">-</span>';
    const safe = escapeHtml(technique);
    return `<span class="tech-id filter-value" data-filter="filter-technique" data-value="${safe}" title="Filter by ${safe}">${safe}</span>`;
}

/**
 * Render a clickable session identifier cell, or a plain dash when absent.
 * @param {string} sessionId
 * @returns {string}
 */
function sessionCell(sessionId) {
    if (!sessionId) return '<span class="tech-id">-</span>';
    const safe = escapeHtml(sessionId);
    return `<span class="tech-id filter-value" data-filter="filter-session" data-value="${safe}" title="Filter by ${safe}">${safe}</span>`;
}

/**
 * Set a filter input to the clicked value and reload the table.
 * @param {string} inputId
 * @param {string} value
 */
function filterByValue(inputId, value) {
    document.getElementById(inputId).value = value;
    loadEvents();
}

/**
 * Render the Prev/Next controls and the page indicator for the current page.
 */
function renderPagination() {
    const container = document.getElementById('events-pagination');
    const perPage = parseInt(document.getElementById('per-page').value, 10);
    const total = eventRows.length;
    const pageCount = Math.max(1, Math.ceil(total / perPage));
    if (currentPage > pageCount) currentPage = pageCount;
    const info = total
        ? `Page ${currentPage} of ${pageCount} &middot; ${total} event${total === 1 ? '' : 's'}`
        : 'No events';
    container.innerHTML = `
        <button class="btn btn-sm" id="page-prev" ${currentPage <= 1 ? 'disabled' : ''}>&laquo; Prev</button>
        <span class="page-info">${info}</span>
        <button class="btn btn-sm" id="page-next" ${currentPage >= pageCount ? 'disabled' : ''}>Next &raquo;</button>`;
    document.getElementById('page-prev').addEventListener('click', () => { currentPage--; renderPage(); });
    document.getElementById('page-next').addEventListener('click', () => { currentPage++; renderPage(); });
}

document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('apply-btn').addEventListener('click', loadEvents);
    ['filter-technique', 'filter-session'].forEach(id =>
        document.getElementById(id).addEventListener('keydown', e => { if (e.key === 'Enter') loadEvents(); }));
    document.getElementById('filter-severity').addEventListener('change', loadEvents);
    document.getElementById('per-page').addEventListener('change', () => { currentPage = 1; renderPage(); });
    loadEvents();
});
