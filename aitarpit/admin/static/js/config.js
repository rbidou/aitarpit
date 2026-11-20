/* AI Tarpit Admin - Configuration editor
 *
 * Two interchangeable editors over the same configuration object:
 *   - a guided HTML form (default), rendered from the field specs below;
 *   - the raw JSON textarea.
 * Both build a plain config object and reuse the server-side validate/save
 * endpoints. Sections the form does not manage (notably `techniques`, which
 * has its own page) are preserved untouched from the loaded configuration.
 */

const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'];
const FACILITIES = ['kern', 'user', 'daemon', 'auth', 'authpriv', 'security',
    'local0', 'local1', 'local2', 'local3', 'local4', 'local5', 'local6', 'local7'];

/* Field specs for the single-object sections, in render order. */
const SECTION_SPECS = [
    {
        key: 'persona', title: 'Persona', fields: [
            { key: 'company', label: 'Company', type: 'text', required: true },
            { key: 'short_name', label: 'Short name', type: 'text' },
            { key: 'domain', label: 'Domain', type: 'text', required: true },
            { key: 'industry', label: 'Industry', type: 'text' },
            { key: 'city', label: 'City', type: 'text' },
            { key: 'seed', label: 'Seed', type: 'int', required: true },
            { key: 'employees', label: 'Employees', type: 'int', min: 5, max: 500 },
            { key: 'services', label: 'Services', type: 'list', desc: 'Comma-separated service names.' },
        ],
    },
    {
        key: 'decoy', title: 'Decoy listener', fields: [
            { key: 'host', label: 'Host', type: 'text' },
            { key: 'port', label: 'Port', type: 'int', min: 1, max: 65535 },
            { key: 'server_header', label: 'Server header', type: 'text' },
            { key: 'session_cookie', label: 'Session cookie', type: 'text' },
            { key: 'threads', label: 'Threads', type: 'int', min: 4, max: 1024 },
            { key: 'trust_proxy', label: 'Trust proxy headers', type: 'bool' },
        ],
    },
    {
        key: 'admin', title: 'Admin listener', fields: [
            { key: 'enabled', label: 'Enabled', type: 'bool' },
            { key: 'host', label: 'Host', type: 'text' },
            { key: 'port', label: 'Port', type: 'int', min: 1, max: 65535 },
            { key: 'token', label: 'Token', type: 'text', desc: 'Leave blank to auto-generate at startup.' },
        ],
    },
    {
        key: 'storage', title: 'Storage', fields: [
            { key: 'path', label: 'Database path', type: 'text', required: true },
            { key: 'max_body_bytes', label: 'Max stored body bytes', type: 'int', min: 0 },
            { key: 'store_request_headers', label: 'Store request headers', type: 'bool' },
            { key: 'store_request_bodies', label: 'Store request bodies', type: 'bool' },
        ],
    },
    {
        key: 'limits', title: 'Limits', fields: [
            { key: 'max_slow_connections', label: 'Max slow connections', type: 'int', min: 0 },
            { key: 'max_bytes_per_session', label: 'Max bytes per session', type: 'int', min: 0 },
            { key: 'max_body_bytes', label: 'Max body bytes', type: 'int', min: 0 },
            { key: 'session_idle_timeout', label: 'Session idle timeout (s)', type: 'int', min: 60 },
        ],
    },
];

/* Console alert sub-section (part of `alerts`). */
const CONSOLE_FIELDS = [
    { key: 'enabled', label: 'Enabled', type: 'bool' },
    { key: 'color', label: 'Colored output', type: 'bool' },
    { key: 'show_requests', label: 'Show requests', type: 'bool' },
    { key: 'min_severity', label: 'Minimum severity', type: 'select', options: SEVERITIES },
];

/* Repeatable syslog sink fields. */
const SYSLOG_FIELDS = [
    { key: 'enabled', label: 'Enabled', type: 'bool' },
    { key: 'name', label: 'Name', type: 'text' },
    { key: 'host', label: 'Host', type: 'text', required: true },
    { key: 'port', label: 'Port', type: 'int', min: 1, max: 65535, required: true },
    { key: 'protocol', label: 'Protocol', type: 'select', options: ['udp', 'tcp'] },
    { key: 'framing', label: 'Framing', type: 'select', options: ['octet-counting', 'newline'] },
    { key: 'facility', label: 'Facility', type: 'select', options: FACILITIES },
    { key: 'app_name', label: 'App name', type: 'text' },
    { key: 'format', label: 'Format', type: 'select', options: ['rfc5424', 'cef', 'json'] },
    { key: 'min_severity', label: 'Minimum severity', type: 'select', options: SEVERITIES },
    { key: 'timeout', label: 'Timeout (s)', type: 'number', min: 0 },
];

/* Repeatable webhook sink fields (auth and headers handled separately). */
const WEBHOOK_FIELDS = [
    { key: 'enabled', label: 'Enabled', type: 'bool' },
    { key: 'name', label: 'Name', type: 'text' },
    { key: 'url', label: 'URL', type: 'text', required: true, desc: 'Must start with http:// or https://.' },
    { key: 'method', label: 'Method', type: 'select', options: ['POST', 'PUT'] },
    { key: 'min_severity', label: 'Minimum severity', type: 'select', options: SEVERITIES },
    { key: 'timeout', label: 'Timeout (s)', type: 'number', min: 0 },
    { key: 'retries', label: 'Retries', type: 'int', min: 0, max: 10 },
    { key: 'verify_tls', label: 'Verify TLS', type: 'bool' },
];

/* Auth type -> the extra fields it requires. */
const AUTH_FIELDS = {
    none: [],
    bearer: [{ key: 'token', label: 'Token' }],
    basic: [{ key: 'username', label: 'Username' }, { key: 'password', label: 'Password' }],
    header: [{ key: 'header', label: 'Header name' }, { key: 'value', label: 'Header value' }],
    hmac: [{ key: 'secret', label: 'Secret' }],
};

/* Defaults for a freshly added sink (mirror of config/defaults.py). */
const SYSLOG_NEW = {
    enabled: true, name: 'syslog', host: '127.0.0.1', port: 514, protocol: 'udp',
    framing: 'octet-counting', facility: 'local0', app_name: 'aitarpit',
    format: 'rfc5424', min_severity: 'low', timeout: 5.0,
};
const WEBHOOK_NEW = {
    enabled: true, name: 'webhook', url: 'https://', method: 'POST', headers: {},
    auth: { type: 'none' }, timeout: 10.0, verify_tls: true, retries: 3, min_severity: 'medium',
};

let loadedConfig = {};
let currentMode = 'form';

/* ---------- field rendering ---------- */

/**
 * Render one field (label + control) from its spec and current value.
 * @param {string} prefix - DOM id prefix making the control unique
 * @param {object} spec - field spec
 * @param {*} value - current value
 * @returns {string} HTML
 */
function renderField(prefix, spec, value) {
    const id = `${prefix}-${spec.key}`;
    const desc = spec.desc ? `<p class="field-description">${escapeHtml(spec.desc)}</p>` : '';
    if (spec.type === 'bool') {
        const checked = value ? 'checked' : '';
        return `<label class="toggle-row" style="justify-content:space-between;">
            <span class="toggle-label">${escapeHtml(spec.label)}</span>
            <span class="toggle-switch"><input type="checkbox" id="${id}" ${checked}>
                <span class="toggle-slider"></span></span></label>`;
    }
    let control;
    if (spec.type === 'select') {
        const opts = spec.options.map(o =>
            `<option value="${escapeHtml(o)}" ${o === value ? 'selected' : ''}>${escapeHtml(o)}</option>`).join('');
        control = `<select class="form-control form-control-sm" id="${id}">${opts}</select>`;
    } else if (spec.type === 'list') {
        const text = Array.isArray(value) ? value.join(', ') : '';
        control = `<input type="text" class="form-control form-control-sm" id="${id}" value="${escapeHtml(text)}">`;
    } else if (spec.type === 'int' || spec.type === 'number') {
        const step = spec.type === 'int' ? '1' : 'any';
        const bounds = `${spec.min != null ? `min="${spec.min}"` : ''} ${spec.max != null ? `max="${spec.max}"` : ''}`;
        const v = (value === undefined || value === null) ? '' : value;
        control = `<input type="number" step="${step}" ${bounds} class="form-control form-control-sm" id="${id}" value="${escapeHtml(String(v))}">`;
    } else {
        const v = (value === undefined || value === null) ? '' : value;
        control = `<input type="text" class="form-control form-control-sm" id="${id}" value="${escapeHtml(String(v))}">`;
    }
    const req = spec.required ? ' <span style="color:var(--danger);">*</span>' : '';
    return `<div class="form-group"><label for="${id}">${escapeHtml(spec.label)}${req}</label>${desc}${control}</div>`;
}

/**
 * Render a card of fields for one named section.
 * @param {string} prefix - DOM id prefix
 * @param {string} title - card heading
 * @param {Array<object>} fields - field specs
 * @param {object} data - current section values
 * @param {string} extra - extra HTML appended inside the card
 * @returns {string} HTML
 */
function renderCard(prefix, title, fields, data, extra = '') {
    const body = fields.map(f => renderField(prefix, f, (data || {})[f.key])).join('');
    return `<section class="cfg-section"><h4>${escapeHtml(title)}</h4>${body}${extra}</section>`;
}

/**
 * Render the auth block for a webhook card, with only the active type's fields.
 * @param {number} i - sink index
 * @param {object} auth - current auth object
 * @returns {string} HTML
 */
function renderAuth(i, auth) {
    const type = (auth && auth.type) || 'none';
    const sel = ['none', 'bearer', 'basic', 'header', 'hmac'].map(t =>
        `<option value="${t}" ${t === type ? 'selected' : ''}>${t}</option>`).join('');
    const extra = (AUTH_FIELDS[type] || []).map(f =>
        `<div class="form-group"><label for="wh-${i}-auth-${f.key}">${escapeHtml(f.label)}</label>
            <input type="text" class="form-control form-control-sm" id="wh-${i}-auth-${f.key}"
                value="${escapeHtml((auth && auth[f.key]) || '')}"></div>`).join('');
    return `<div class="form-group"><label for="wh-${i}-auth-type">Auth type</label>
        <select class="form-control form-control-sm auth-type" id="wh-${i}-auth-type" data-idx="${i}">${sel}</select></div>
        <div id="wh-${i}-auth-extra">${extra}</div>`;
}

/**
 * Render one repeatable sink card (syslog or webhook).
 * @param {'syslog'|'webhook'} kind
 * @param {number} i - index
 * @param {object} data - sink values
 * @returns {string} HTML
 */
function renderSinkCard(kind, i, data) {
    const prefix = kind === 'syslog' ? `sl-${i}` : `wh-${i}`;
    const fields = kind === 'syslog' ? SYSLOG_FIELDS : WEBHOOK_FIELDS;
    const title = `${kind === 'syslog' ? 'Syslog' : 'Webhook'} #${i + 1}`;
    let extra = `<button type="button" class="btn btn-sm btn-danger remove-sink" data-kind="${kind}" data-idx="${i}"
        style="margin-top:8px;">Remove</button>`;
    if (kind === 'webhook') {
        const headersText = Object.entries(data.headers || {}).map(([k, v]) => `${k}: ${v}`).join('\n');
        const headers = `<div class="form-group"><label for="wh-${i}-headers">Headers</label>
            <p class="field-description">One <code>Name: value</code> per line.</p>
            <textarea class="form-control form-control-mono form-control-sm" id="wh-${i}-headers" rows="2"
                spellcheck="false">${escapeHtml(headersText)}</textarea></div>`;
        extra = renderAuth(i, data.auth) + headers + extra;
    }
    return `<section class="cfg-section sink-card" data-kind="${kind}" data-idx="${i}">
        <h4>${escapeHtml(title)}</h4>${fields.map(f => renderField(prefix, f, data[f.key])).join('')}${extra}</section>`;
}

/**
 * Render the full form from a configuration object.
 * @param {object} cfg
 */
function renderForm(cfg) {
    const sections = SECTION_SPECS.map(s => renderCard(s.key, s.title, s.fields, cfg[s.key])).join('');
    const alerts = cfg.alerts || {};
    const consoleCard = renderCard('console', 'Console alerts', CONSOLE_FIELDS, alerts.console);
    const syslog = (alerts.syslog || []).map((s, i) => renderSinkCard('syslog', i, s)).join('') +
        `<button type="button" class="btn btn-sm add-sink" data-kind="syslog">+ Add syslog sink</button>`;
    const webhooks = (alerts.webhooks || []).map((w, i) => renderSinkCard('webhook', i, w)).join('') +
        `<button type="button" class="btn btn-sm add-sink" data-kind="webhook">+ Add webhook</button>`;
    document.getElementById('config-form').innerHTML = sections + consoleCard +
        `<div class="cfg-span"><h3 class="cfg-group-title">Syslog sinks</h3><div class="sink-list">${syslog}</div></div>` +
        `<div class="cfg-span"><h3 class="cfg-group-title">Webhooks</h3><div class="sink-list">${webhooks}</div></div>`;
}

/* ---------- form collection ---------- */

/**
 * Read a value from a rendered control into the section object.
 * @param {object} out - target object
 * @param {string} prefix - DOM id prefix
 * @param {object} spec - field spec
 */
function collectField(out, prefix, spec) {
    const el = document.getElementById(`${prefix}-${spec.key}`);
    if (!el) return;
    if (spec.type === 'bool') {
        out[spec.key] = el.checked;
        return;
    }
    const raw = el.value.trim();
    if (spec.type === 'list') {
        out[spec.key] = raw ? raw.split(',').map(s => s.trim()).filter(Boolean) : [];
        return;
    }
    if (spec.type === 'select') {
        out[spec.key] = el.value;
        return;
    }
    if (raw === '') return;
    if (spec.type === 'int') out[spec.key] = parseInt(raw, 10);
    else if (spec.type === 'number') out[spec.key] = Number(raw);
    else out[spec.key] = raw;
}

/**
 * Collect all fields of a spec list into a new object.
 * @param {string} prefix
 * @param {Array<object>} fields
 * @returns {object}
 */
function collectFields(prefix, fields) {
    const out = {};
    fields.forEach(f => collectField(out, prefix, f));
    return out;
}

/**
 * Collect the auth object of a webhook card by its active type.
 * @param {number} i - index
 * @returns {object}
 */
function collectAuth(i) {
    const type = document.getElementById(`wh-${i}-auth-type`).value;
    const auth = { type };
    (AUTH_FIELDS[type] || []).forEach(f => {
        const el = document.getElementById(`wh-${i}-auth-${f.key}`);
        const v = el ? el.value.trim() : '';
        if (v) auth[f.key] = v;
    });
    return auth;
}

/**
 * Collect one webhook's headers from its textarea.
 * @param {number} i - index
 * @returns {object}
 */
function collectHeaders(i) {
    const el = document.getElementById(`wh-${i}-headers`);
    const headers = {};
    if (el) {
        el.value.split('\n').forEach(line => {
            const idx = line.indexOf(':');
            if (idx <= 0) return;
            const k = line.slice(0, idx).trim();
            if (k) headers[k] = line.slice(idx + 1).trim();
        });
    }
    return headers;
}

/**
 * Build a configuration object from the current form state.
 * Unmanaged sections (e.g. techniques) are kept from the loaded config.
 * @returns {object}
 */
function collectForm() {
    const out = JSON.parse(JSON.stringify(loadedConfig));
    SECTION_SPECS.forEach(s => { out[s.key] = collectFields(s.key, s.fields); });
    out.alerts = out.alerts || {};
    out.alerts.console = collectFields('console', CONSOLE_FIELDS);
    out.alerts.syslog = Array.from(document.querySelectorAll('.sink-card[data-kind="syslog"]'))
        .map(card => collectFields(`sl-${card.dataset.idx}`, SYSLOG_FIELDS));
    out.alerts.webhooks = Array.from(document.querySelectorAll('.sink-card[data-kind="webhook"]'))
        .map(card => {
            const i = card.dataset.idx;
            const wh = collectFields(`wh-${i}`, WEBHOOK_FIELDS);
            wh.headers = collectHeaders(i);
            wh.auth = collectAuth(i);
            return wh;
        });
    return out;
}

/* ---------- sink add / remove ---------- */

/**
 * Re-read the form into loadedConfig, then re-render it. Used so edits
 * survive structural changes (adding or removing a sink).
 */
function reRenderFromForm() {
    loadedConfig = collectForm();
    renderForm(loadedConfig);
}

/**
 * Add a sink of the given kind, preserving current edits.
 * @param {'syslog'|'webhook'} kind
 */
function handleAddSink(kind) {
    loadedConfig = collectForm();
    loadedConfig.alerts = loadedConfig.alerts || {};
    const list = kind === 'syslog' ? 'syslog' : 'webhooks';
    loadedConfig.alerts[list] = loadedConfig.alerts[list] || [];
    loadedConfig.alerts[list].push(JSON.parse(JSON.stringify(kind === 'syslog' ? SYSLOG_NEW : WEBHOOK_NEW)));
    renderForm(loadedConfig);
}

/**
 * Remove the sink at the given index, preserving current edits.
 * @param {'syslog'|'webhook'} kind
 * @param {number} idx
 */
function handleRemoveSink(kind, idx) {
    loadedConfig = collectForm();
    const list = kind === 'syslog' ? 'syslog' : 'webhooks';
    (loadedConfig.alerts[list] || []).splice(idx, 1);
    renderForm(loadedConfig);
}

/* ---------- mode switching ---------- */

/** Parse the raw textarea, reporting a JSON error inline. */
function parsedRaw() {
    try {
        return JSON.parse(document.getElementById('config-text').value);
    } catch (err) {
        setResult(`Invalid JSON: ${escapeHtml(err.message)}`, 'danger');
        return null;
    }
}

/**
 * Switch between the form and raw editors, carrying edits across.
 * @param {'form'|'raw'} mode
 */
function switchMode(mode) {
    if (mode === currentMode) return;
    if (mode === 'raw') {
        document.getElementById('config-text').value = JSON.stringify(collectForm(), null, 2);
    } else {
        const cfg = parsedRaw();
        if (!cfg) return;
        loadedConfig = cfg;
        renderForm(loadedConfig);
    }
    currentMode = mode;
    document.getElementById('config-form-view').style.display = mode === 'form' ? '' : 'none';
    document.getElementById('config-raw-view').style.display = mode === 'raw' ? '' : 'none';
    document.querySelectorAll('#mode-toggle .seg-btn').forEach(b =>
        b.classList.toggle('active', b.dataset.mode === mode));
    setResult('', 'success');
}

/**
 * Build the config object from whichever editor is active.
 * @returns {object|null}
 */
function activeConfig() {
    return currentMode === 'raw' ? parsedRaw() : collectForm();
}

/* ---------- result line, load, validate, save ---------- */

/**
 * Show a result line.
 * @param {string} html
 * @param {'success'|'danger'} kind
 */
function setResult(html, kind) {
    document.getElementById('config-result').innerHTML =
        html ? `<span style="color:var(--${kind});">${html}</span>` : '';
}

/** Load the active configuration into both editors. */
async function loadConfig() {
    const resp = await adminFetch('/api/admin/config');
    if (!resp.status) {
        notify(resp.message || 'Failed to load config', 'error');
        return;
    }
    loadedConfig = resp.data.config || {};
    renderForm(loadedConfig);
    document.getElementById('config-text').value = JSON.stringify(loadedConfig, null, 2);
    document.getElementById('config-path').textContent =
        resp.data.path ? `File: ${resp.data.path}` : 'Running from built-in defaults - saving is disabled (start with -c FILE).';
}

/** Validate the edited configuration against the schema. */
async function handleValidate() {
    const cfg = activeConfig();
    if (!cfg) return;
    const resp = await adminFetch('/api/admin/config/validate', { method: 'POST', body: cfg });
    if (resp.status) {
        setResult('Configuration is valid.', 'success');
    } else {
        const errs = (resp.data && resp.data.errors || []).map(escapeHtml).join('<br>');
        setResult(`${escapeHtml(resp.message)}<br>${errs}`, 'danger');
    }
}

/** Save the edited configuration to the config file. */
async function handleSave() {
    const cfg = activeConfig();
    if (!cfg) return;
    if (!confirm('Save configuration? Changes apply when the honeypot is restarted.')) return;
    const resp = await adminFetch('/api/admin/config', { method: 'PUT', body: cfg });
    if (resp.status) {
        setResult(escapeHtml(resp.message), 'success');
        notify('Configuration saved', 'success');
    } else {
        const errs = (resp.data && resp.data.errors || []).map(escapeHtml).join('<br>');
        setResult(`${escapeHtml(resp.message)}<br>${errs}`, 'danger');
    }
}

document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('validate-btn').addEventListener('click', handleValidate);
    document.getElementById('save-btn').addEventListener('click', handleSave);
    document.getElementById('mode-toggle').addEventListener('click', e => {
        const btn = e.target.closest('.seg-btn');
        if (btn) switchMode(btn.dataset.mode);
    });
    document.getElementById('config-form').addEventListener('click', e => {
        const add = e.target.closest('.add-sink');
        if (add) { handleAddSink(add.dataset.kind); return; }
        const rm = e.target.closest('.remove-sink');
        if (rm) handleRemoveSink(rm.dataset.kind, parseInt(rm.dataset.idx, 10));
    });
    document.getElementById('config-form').addEventListener('change', e => {
        const sel = e.target.closest('.auth-type');
        if (sel) {
            const i = sel.dataset.idx;
            document.getElementById(`wh-${i}-auth-extra`).innerHTML =
                (AUTH_FIELDS[sel.value] || []).map(f =>
                    `<div class="form-group"><label for="wh-${i}-auth-${f.key}">${escapeHtml(f.label)}</label>
                        <input type="text" class="form-control form-control-sm" id="wh-${i}-auth-${f.key}"></div>`).join('');
        }
    });
    loadConfig();
});
