/* AI Tarpit Admin - API wrapper that attaches the admin token.
 *
 * The admin UI is same-origin with the token-protected API. The token is
 * injected into the page by the server (loopback-only surface) and attached
 * here so page scripts can use apiFetch's envelope contract via adminFetch.
 */

/**
 * Fetch an admin API endpoint, attaching the admin token header.
 * @param {string} url
 * @param {object} options - fetch options (body may be an object)
 * @returns {Promise<object>} the parsed API envelope
 */
async function adminFetch(url, options = {}) {
    const merged = { ...options };
    merged.headers = { ...(options.headers || {}), 'X-Admin-Token': window.AITARPIT_ADMIN_TOKEN || '' };
    return apiFetch(url, merged);
}

/**
 * Show one of the standard loading/results/error sections, hiding the others.
 * Missing sections are ignored, so pages may omit the ones they do not use.
 * @param {'loading'|'results'|'error'|'none'} section
 */
function showSection(section) {
    [['loading', 'loading-section'], ['results', 'results-section'], ['error', 'error-section']]
        .forEach(([name, id]) => {
            const el = document.getElementById(id);
            if (el) el.style.display = section === name ? '' : 'none';
        });
}

/**
 * Render an inline error message into the standard error section.
 * @param {string} message
 */
function showError(message) {
    const el = document.getElementById('error-message');
    if (el) el.textContent = message;
    showSection('error');
}

/**
 * Format an epoch-seconds timestamp as a short local date-time string.
 * @param {number} ts
 * @returns {string}
 */
function formatTs(ts) {
    if (!ts) return '';
    return new Date(ts * 1000).toISOString().replace('T', ' ').slice(0, 19);
}

/** Badge class per event severity. */
const SEVERITY_BADGE = {
    info: 'badge-neutral', low: 'badge-info', medium: 'badge-warning',
    high: 'badge-danger', critical: 'badge-danger',
};

/** Badge class per session classification. */
const CLASS_BADGE = {
    ai_agent: 'badge-danger', scanner: 'badge-warning', human: 'badge-success', unknown: 'badge-neutral',
};
