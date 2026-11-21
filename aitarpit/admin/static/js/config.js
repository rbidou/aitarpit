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
            { key: 'prune_enabled', label: 'Auto-remove old data', type: 'bool',
                desc: 'Periodically delete events and sessions older than the retention period.' },
            { key: 'prune_after_days', label: 'Retention (days)', type: 'int', min: 1 },
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

/* Which single-object sections render under each form tab, in order. */
const TAB_SECTIONS = {
    persona: ['persona'],
    decoy: ['decoy', 'limits'],
    admin: ['admin', 'storage'],
};

/** Look up a section spec by its key. */
function sectionSpec(key) {
    return SECTION_SPECS.find(s => s.key === key);
}

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
 * Render the active auth type's extra fields (shared by the initial render
 * and the auth-type change handler).
 * @param {string} prefix - DOM id prefix
 * @param {string} type - auth type
 * @param {object} auth - current auth object (may be undefined)
 * @returns {string} HTML
 */
function renderAuthExtra(prefix, type, auth) {
    return (AUTH_FIELDS[type] || []).map(f =>
        `<div class="form-group"><label for="${prefix}-auth-${f.key}">${escapeHtml(f.label)}</label>
            <input type="text" class="form-control form-control-sm" id="${prefix}-auth-${f.key}"
                value="${escapeHtml((auth && auth[f.key]) || '')}"></div>`).join('');
}

/**
 * Render the auth block for a webhook, with only the active type's fields.
 * @param {string} prefix - DOM id prefix
 * @param {object} auth - current auth object
 * @returns {string} HTML
 */
function renderAuth(prefix, auth) {
    const type = (auth && auth.type) || 'none';
    const sel = ['none', 'bearer', 'basic', 'header', 'hmac'].map(t =>
        `<option value="${t}" ${t === type ? 'selected' : ''}>${t}</option>`).join('');
    return `<div class="form-group"><label for="${prefix}-auth-type">Auth type</label>
        <select class="form-control form-control-sm auth-type" id="${prefix}-auth-type" data-prefix="${prefix}">${sel}</select></div>
        <div id="${prefix}-auth-extra">${renderAuthExtra(prefix, type, auth)}</div>`;
}

/**
 * Render the editable fields for one sink inside the modal body.
 * @param {'syslog'|'webhook'} kind
 * @param {object} data - sink values
 * @returns {string} HTML
 */
function renderSinkFields(kind, data) {
    const fields = kind === 'syslog' ? SYSLOG_FIELDS : WEBHOOK_FIELDS;
    let html = fields.map(f => renderField('m', f, data[f.key])).join('');
    if (kind === 'webhook') {
        const headersText = Object.entries(data.headers || {}).map(([k, v]) => `${k}: ${v}`).join('\n');
        html += renderAuth('m', data.auth) +
            `<div class="form-group"><label for="m-headers">Headers</label>
                <p class="field-description">One <code>Name: value</code> per line.</p>
                <textarea class="form-control form-control-mono form-control-sm" id="m-headers" rows="3"
                    spellcheck="false">${escapeHtml(headersText)}</textarea></div>`;
    }
    return html;
}

/**
 * Render one sink table (syslog or webhook) with per-row edit/delete and an
 * add button, from the current sink array.
 * @param {'syslog'|'webhook'} kind
 * @param {Array<object>} sinks
 * @returns {string} HTML
 */
function renderSinkTable(kind, sinks) {
    const isSyslog = kind === 'syslog';
    const heads = isSyslog
        ? ['Name', 'Host:Port', 'Protocol', 'Format', 'Min severity', 'Status', '']
        : ['Name', 'URL', 'Method', 'Auth', 'Min severity', 'Status', ''];
    const rows = (sinks || []).map((s, i) => {
        const status = s.enabled
            ? '<span class="badge badge-success">on</span>'
            : '<span class="badge badge-neutral">off</span>';
        const cells = isSyslog
            ? [escapeHtml(s.name || ''),
               `<span class="mono">${escapeHtml(`${s.host || ''}:${s.port != null ? s.port : ''}`)}</span>`,
               escapeHtml(s.protocol || ''), escapeHtml(s.format || ''), escapeHtml(s.min_severity || '')]
            : [escapeHtml(s.name || ''),
               `<span class="mono">${escapeHtml(s.url || '')}</span>`,
               escapeHtml(s.method || ''), escapeHtml((s.auth && s.auth.type) || 'none'),
               escapeHtml(s.min_severity || '')];
        return `<tr><td>${cells.join('</td><td>')}</td><td>${status}</td>
            <td class="cfg-row-actions">
                <button type="button" class="btn btn-sm edit-sink" data-kind="${kind}" data-idx="${i}">Edit</button>
                <button type="button" class="btn btn-sm btn-danger del-sink" data-kind="${kind}" data-idx="${i}">Delete</button>
            </td></tr>`;
    }).join('');
    const body = rows ||
        `<tr><td colspan="${heads.length}" class="text-muted">No ${isSyslog ? 'syslog sinks' : 'webhooks'} configured.</td></tr>`;
    const label = isSyslog ? 'Syslog sinks' : 'Webhooks';
    const addLabel = isSyslog ? '+ Add syslog sink' : '+ Add webhook';
    return `<div class="cfg-sink-group">
        <div class="cfg-sink-head">
            <h3 class="cfg-group-title">${label}</h3>
            <button type="button" class="btn btn-sm add-sink" data-kind="${kind}">${addLabel}</button>
        </div>
        <table class="data-table"><thead><tr><th>${heads.join('</th><th>')}</th></tr></thead>
            <tbody>${body}</tbody></table>
    </div>`;
}

/**
 * Render the Events tab (syslog + webhook tables) from the config's alerts.
 * @param {object} cfg
 */
function renderEventsTab(cfg) {
    const alerts = cfg.alerts || {};
    document.getElementById('cfg-panel-events').innerHTML =
        renderSinkTable('syslog', alerts.syslog) + renderSinkTable('webhook', alerts.webhooks);
}

/**
 * Render the full tabbed form from a configuration object.
 * @param {object} cfg
 */
function renderForm(cfg) {
    Object.entries(TAB_SECTIONS).forEach(([tab, keys]) => {
        document.getElementById(`cfg-panel-${tab}`).innerHTML = keys.map(k => {
            const spec = sectionSpec(k);
            return renderCard(spec.key, spec.title, spec.fields, cfg[spec.key]);
        }).join('');
    });
    document.getElementById('cfg-panel-console').innerHTML =
        renderCard('console', 'Console alerts', CONSOLE_FIELDS, (cfg.alerts || {}).console);
    renderEventsTab(cfg);
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
 * Collect a webhook auth object from its controls by the active type.
 * @param {string} prefix - DOM id prefix
 * @returns {object}
 */
function collectAuth(prefix) {
    const type = document.getElementById(`${prefix}-auth-type`).value;
    const auth = { type };
    (AUTH_FIELDS[type] || []).forEach(f => {
        const el = document.getElementById(`${prefix}-auth-${f.key}`);
        const v = el ? el.value.trim() : '';
        if (v) auth[f.key] = v;
    });
    return auth;
}

/**
 * Collect a webhook's headers from its textarea.
 * @param {string} prefix - DOM id prefix
 * @returns {object}
 */
function collectHeaders(prefix) {
    const el = document.getElementById(`${prefix}-headers`);
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
 * Build a configuration object from the current form state. The syslog/webhook
 * sink arrays are the authoritative in-memory copy (kept current by the modal),
 * so they pass through the deep copy of loadedConfig untouched. Unmanaged
 * sections (e.g. techniques) are likewise kept from the loaded config.
 * @returns {object}
 */
function collectForm() {
    const out = JSON.parse(JSON.stringify(loadedConfig));
    SECTION_SPECS.forEach(s => { out[s.key] = collectFields(s.key, s.fields); });
    out.alerts = out.alerts || {};
    out.alerts.console = collectFields('console', CONSOLE_FIELDS);
    return out;
}

/* ---------- sink modal: add / edit / delete ---------- */

let modalKind = null;
let modalIdx = null;

/** The alerts list name for a sink kind. */
function sinkListName(kind) {
    return kind === 'syslog' ? 'syslog' : 'webhooks';
}

/**
 * Open the sink modal to add (idx null) or edit an existing sink.
 * @param {'syslog'|'webhook'} kind
 * @param {?number} idx - sink index, or null to add a new one
 */
function openSinkModal(kind, idx) {
    modalKind = kind;
    modalIdx = idx;
    const source = idx === null
        ? (kind === 'syslog' ? SYSLOG_NEW : WEBHOOK_NEW)
        : (loadedConfig.alerts[sinkListName(kind)][idx]);
    const data = JSON.parse(JSON.stringify(source));
    const noun = kind === 'syslog' ? 'syslog sink' : 'webhook';
    document.getElementById('sink-modal-title').textContent = `${idx === null ? 'Add' : 'Edit'} ${noun}`;
    document.getElementById('sink-modal-body').innerHTML = renderSinkFields(kind, data);
    document.getElementById('sink-modal').hidden = false;
}

/** Close the sink modal and clear its state. */
function closeSinkModal() {
    document.getElementById('sink-modal').hidden = true;
    document.getElementById('sink-modal-body').innerHTML = '';
    modalKind = null;
    modalIdx = null;
}

/** Collect the edited sink from the modal into a plain object. */
function collectSinkModal(kind) {
    const out = collectFields('m', kind === 'syslog' ? SYSLOG_FIELDS : WEBHOOK_FIELDS);
    if (kind === 'webhook') {
        out.headers = collectHeaders('m');
        out.auth = collectAuth('m');
    }
    return out;
}

/** Save the modal's sink into the config and re-render the Events tab. */
function handleSaveSink() {
    const list = sinkListName(modalKind);
    loadedConfig.alerts = loadedConfig.alerts || {};
    loadedConfig.alerts[list] = loadedConfig.alerts[list] || [];
    const data = collectSinkModal(modalKind);
    if (modalIdx === null) loadedConfig.alerts[list].push(data);
    else loadedConfig.alerts[list][modalIdx] = data;
    closeSinkModal();
    renderEventsTab(loadedConfig);
}

/**
 * Delete the sink at the given index after confirmation.
 * @param {'syslog'|'webhook'} kind
 * @param {number} idx
 */
function handleDeleteSink(kind, idx) {
    if (!confirm('Delete this entry?')) return;
    const list = sinkListName(kind);
    (loadedConfig.alerts[list] || []).splice(idx, 1);
    renderEventsTab(loadedConfig);
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
    document.getElementById('cfg-tabs').addEventListener('click', e => {
        const btn = e.target.closest('.cfg-tab');
        if (!btn) return;
        document.querySelectorAll('.cfg-tab').forEach(b => b.classList.toggle('active', b === btn));
        document.querySelectorAll('.cfg-tab-panel').forEach(p => { p.hidden = p.dataset.tab !== btn.dataset.tab; });
    });
    document.getElementById('cfg-panel-events').addEventListener('click', e => {
        const add = e.target.closest('.add-sink');
        if (add) { openSinkModal(add.dataset.kind, null); return; }
        const edit = e.target.closest('.edit-sink');
        if (edit) { openSinkModal(edit.dataset.kind, parseInt(edit.dataset.idx, 10)); return; }
        const del = e.target.closest('.del-sink');
        if (del) handleDeleteSink(del.dataset.kind, parseInt(del.dataset.idx, 10));
    });
    document.getElementById('sink-modal-body').addEventListener('change', e => {
        const sel = e.target.closest('.auth-type');
        if (sel) {
            const p = sel.dataset.prefix;
            document.getElementById(`${p}-auth-extra`).innerHTML = renderAuthExtra(p, sel.value, null);
        }
    });
    document.getElementById('sink-modal-save').addEventListener('click', handleSaveSink);
    document.getElementById('sink-modal-cancel').addEventListener('click', closeSinkModal);
    document.getElementById('sink-modal-close').addEventListener('click', closeSinkModal);
    document.getElementById('sink-modal').addEventListener('click', e => {
        if (e.target.id === 'sink-modal') closeSinkModal();
    });
    loadConfig();
});
