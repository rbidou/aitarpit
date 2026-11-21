/* AI Tarpit Admin - Reports.
 *
 * Renders an interactive activity report: summary cards, a classification pie,
 * an events-by-technique stacked bar and an events-over-time stacked area, with
 * a timeframe selector (default last 7 days) and multi-select filters on event
 * type, severity and classification. All aggregation and charting happen client
 * side from /api/admin/sessions and /api/admin/events; only changing the
 * timeframe refetches. The original text/JSON/CSV/HTML export is kept below.
 */

const TIMEFRAMES = [
    { value: '1', label: 'Last 24 hours', hours: 24 },
    { value: '7', label: 'Last 7 days', hours: 24 * 7 },
    { value: '30', label: 'Last 30 days', hours: 24 * 30 },
    { value: 'all', label: 'All time', hours: null },
];
const DEFAULT_TIMEFRAME = '7';
const TOKENS_PER_BYTE = 0.25; // matches aitarpit/report.py

// Non-attacker-activity events excluded from the report entirely (never charted,
// counted, or offered as an event-type filter option): operational events
// (`system`, `test`) and session lifecycle events (`session.*`).
const EXCLUDED_EVENT_TYPES = new Set(['system', 'test']);

/**
 * Whether an event type is excluded from the report.
 * @param {string} type
 * @returns {boolean}
 */
function isExcludedEvent(type) {
    return EXCLUDED_EVENT_TYPES.has(type) || type.startsWith('session.');
}

const SEVERITY_ORDER = ['info', 'low', 'medium', 'high', 'critical'];
const SEVERITY_LABEL = { info: 'Info', low: 'Low', medium: 'Medium', high: 'High', critical: 'Critical' };
const SEVERITY_COLOR = { info: '#8b949e', low: '#58a6ff', medium: '#d29922', high: '#f85149', critical: '#8b1a1a' };
const CLASS_ORDER = ['ai_agent', 'scanner', 'human', 'unknown'];

const SEVERITY_SERIES = SEVERITY_ORDER.map(k => ({ key: k, label: SEVERITY_LABEL[k], color: SEVERITY_COLOR[k] }));

/* ---- Export (unchanged) ---- */
const EXT = { text: 'txt', json: 'json', csv: 'csv', html: 'html' };
const MIME = { text: 'text/plain', json: 'application/json', csv: 'text/csv', html: 'text/html' };

const state = { sessions: [], events: [], classBySession: new Map(), ms: {} };
let lastContent = '';
let lastFormat = 'text';

/**
 * Resolve the chosen timeframe to an epoch 'since' (null = all time).
 * @returns {number|null}
 */
function currentSince() {
    const tf = TIMEFRAMES.find(t => t.value === document.getElementById('tf-select').value);
    return tf && tf.hours ? Date.now() / 1000 - tf.hours * 3600 : null;
}

/**
 * Fetch sessions and events for the current timeframe, refresh filter options
 * and redraw everything.
 */
async function loadData() {
    const since = currentSince();
    const q = since ? `since=${since}&` : '';
    const [sessions, events] = await Promise.all([
        adminFetch(`/api/admin/sessions?${q}limit=5000`),
        adminFetch(`/api/admin/events?${q}min_severity=info&limit=5000`),
    ]);
    if (!sessions.status || !events.status) {
        showError((sessions.message || events.message) || 'Failed to load report data');
        return;
    }
    state.sessions = sessions.data.sessions || [];
    state.events = (events.data.events || []).filter(e => !isExcludedEvent(e.type));
    state.classBySession = new Map(state.sessions.map(s => [s.id, s.classification || 'unknown']));

    const types = [...new Set(state.events.map(e => e.type))].sort();
    state.ms.type.setOptions(types.map(t => ({ value: t, label: t })));
    state.ms.severity.setOptions(SEVERITY_ORDER.map(s => ({ value: s, label: SEVERITY_LABEL[s] })));
    state.ms.classification.setOptions(CLASS_ORDER.map(c => ({ value: c, label: CLASS_LABEL[c] || c })));

    document.getElementById('report-updated').textContent = `Updated ${formatTs(Date.now() / 1000)}`;
    applyFiltersAndRender();
}

/**
 * Apply the current filters to the loaded data, then repaint cards and charts.
 */
function applyFiltersAndRender() {
    const sevSel = new Set(state.ms.severity.getSelected());
    const typeSel = new Set(state.ms.type.getSelected());
    const classSel = new Set(state.ms.classification.getSelected());

    const sessions = state.sessions.filter(s => classSel.has(s.classification || 'unknown'));
    const events = state.events.filter(e => {
        const cls = state.classBySession.get(e.session_id) || 'unknown';
        return sevSel.has(e.severity) && typeSel.has(e.type) && classSel.has(cls);
    });

    renderCards(sessions, events);
    renderStackedBar(document.getElementById('chart-technique'), groupByTechnique(events), SEVERITY_SERIES);
    renderStackedArea(document.getElementById('chart-timeline'), buildBuckets(events, currentSince()), SEVERITY_SERIES);
}

/**
 * Paint the six summary cards.
 * @param {Array<object>} sessions - filtered sessions
 * @param {Array<object>} events - filtered events
 */
function renderCards(sessions, events) {
    const requests = sessions.reduce((a, s) => a + (s.requests || 0), 0);
    const held = sessions.reduce((a, s) => a + (s.held_seconds || 0), 0);
    const bytes = sessions.reduce((a, s) => a + (s.bytes_out || 0), 0);
    const honeytokens = events.filter(e => e.type === 'honeytoken.used').length;
    const intel = events.filter(e => e.type === 'intel.captured').length;
    const set = (id, v) => { document.getElementById(id).textContent = v; };
    set('card-sessions', sessions.length.toLocaleString());
    set('card-requests', requests.toLocaleString());
    set('card-held', `${Math.round(held).toLocaleString()}s`);
    set('card-tokens', Math.round(bytes * TOKENS_PER_BYTE).toLocaleString());
    set('card-honeytokens', honeytokens.toLocaleString());
    set('card-intel', intel.toLocaleString());
}

/**
 * Group events by technique, each with a per-severity breakdown, busiest first.
 * @param {Array<object>} events
 * @returns {Array<{label:string,values:object}>}
 */
function groupByTechnique(events) {
    const map = new Map();
    events.forEach(e => {
        const key = e.technique || '(none)';
        if (!map.has(key)) {
            const values = {};
            SEVERITY_ORDER.forEach(s => { values[s] = 0; });
            map.set(key, { label: key, values });
        }
        const cat = map.get(key);
        if (cat.values[e.severity] !== undefined) cat.values[e.severity] += 1;
    });
    const total = v => SEVERITY_ORDER.reduce((a, s) => a + v[s], 0);
    return [...map.values()].sort((a, b) => total(b.values) - total(a.values));
}

/**
 * Pick a bucket size (seconds) so the window reads clearly.
 * @param {number} spanSec
 * @returns {number} hourly, 6-hourly or daily step in seconds
 */
function timeStep(spanSec) {
    const DAY = 86400;
    if (spanSec <= 2 * DAY) return 3600;
    if (spanSec <= 10 * DAY) return 6 * 3600;
    return DAY;
}

/**
 * Label a bucket start (UTC, matching the rest of the UI).
 * @param {number} epoch - seconds
 * @param {number} step - bucket size in seconds
 * @returns {string}
 */
function bucketLabel(epoch, step) {
    const d = new Date(epoch * 1000);
    const p = n => String(n).padStart(2, '0');
    const md = `${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())}`;
    return step >= 86400 ? md : `${md} ${p(d.getUTCHours())}:00`;
}

/**
 * Bucket events into an ordered timeline with per-severity counts.
 * @param {Array<object>} events
 * @param {number|null} since - window start (null = span the events' own range)
 * @returns {Array<{label:string,values:object}>}
 */
function buildBuckets(events, since) {
    const now = Date.now() / 1000;
    let start = since;
    let end = now;
    if (start == null) {
        if (!events.length) return [];
        start = Math.min(...events.map(e => e.ts));
        end = Math.max(...events.map(e => e.ts));
    }
    const span = Math.max(end - start, 1);
    const step = timeStep(span);
    start = Math.floor(start / step) * step;
    const n = Math.min(60, Math.max(2, Math.ceil((end - start) / step) + 1));
    const buckets = [];
    for (let i = 0; i < n; i++) {
        const values = {};
        SEVERITY_ORDER.forEach(s => { values[s] = 0; });
        buckets.push({ label: bucketLabel(start + i * step, step), values });
    }
    events.forEach(e => {
        let idx = Math.floor((e.ts - start) / step);
        if (idx < 0) idx = 0;
        if (idx >= n) idx = n - 1;
        if (buckets[idx].values[e.severity] !== undefined) buckets[idx].values[e.severity] += 1;
    });
    return buckets;
}

/**
 * Request a text/JSON/CSV/HTML report and show it in the export block.
 */
async function handleGenerate() {
    const fmt = document.getElementById('report-format').value;
    const hours = parseFloat(document.getElementById('report-hours').value);
    const body = { format: fmt };
    if (!Number.isNaN(hours) && hours > 0) body.since = Date.now() / 1000 - hours * 3600;
    const resp = await adminFetch('/api/admin/report', { method: 'POST', body });
    if (!resp.status) {
        notify(resp.message || 'Report failed', 'error');
        return;
    }
    lastFormat = fmt;
    lastContent = fmt === 'json' ? JSON.stringify(resp.data.report, null, 2) : resp.data.rendered;
    document.getElementById('report-output').textContent = lastContent;
    document.getElementById('export-result').style.display = '';
}

/**
 * Build the timeframe <select> options.
 */
function initTimeframe() {
    const sel = document.getElementById('tf-select');
    sel.innerHTML = TIMEFRAMES.map(t =>
        `<option value="${t.value}"${t.value === DEFAULT_TIMEFRAME ? ' selected' : ''}>${t.label}</option>`).join('');
    sel.addEventListener('change', loadData);
}

document.addEventListener('DOMContentLoaded', () => {
    initTimeframe();
    state.ms.type = createMultiSelect(document.getElementById('ms-type'),
        { label: 'Event type', options: [], onChange: applyFiltersAndRender });
    state.ms.severity = createMultiSelect(document.getElementById('ms-severity'),
        { label: 'Severity', options: [], onChange: applyFiltersAndRender });
    state.ms.classification = createMultiSelect(document.getElementById('ms-class'),
        { label: 'Classification', options: [], onChange: applyFiltersAndRender });

    document.getElementById('generate-btn').addEventListener('click', handleGenerate);
    document.getElementById('copy-btn').addEventListener('click', () => copyToClipboard(lastContent));
    document.getElementById('download-btn').addEventListener('click', () =>
        downloadFile(lastContent, `aitarpit-report.${EXT[lastFormat]}`, MIME[lastFormat]));

    loadData();
});
