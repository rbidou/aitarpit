/* AI Tarpit Admin - Techniques */

let currentConfig = null;

/**
 * Load technique metadata (status) and current options (config), then render.
 */
async function loadTechniques() {
    const [status, config] = await Promise.all([
        adminFetch('/api/admin/status'),
        adminFetch('/api/admin/config'),
    ]);
    if (!status.status || !config.status) {
        notify('Failed to load techniques', 'error');
        return;
    }
    currentConfig = config.data.config;
    renderTechniques(status.data.techniques, currentConfig.techniques || {});
}

/**
 * Render one editable block per technique.
 * @param {Array<object>} techniques - {id,name,summary,enabled}
 * @param {object} configs - techniques config section
 */
function renderTechniques(techniques, configs) {
    const list = document.getElementById('tech-list');
    list.innerHTML = techniques.map(t => {
        const cfg = configs[t.id] || { enabled: t.enabled };
        const options = { ...cfg };
        delete options.enabled;
        const checked = cfg.enabled ? 'checked' : '';
        return `<div style="border:1px solid var(--border);border-radius:8px;padding:12px 16px;">
            <label class="toggle-row" style="justify-content:space-between;">
                <span><span class="tech-id">${escapeHtml(t.id)}</span> <span class="toggle-label">${escapeHtml(t.name)}</span>
                    <span class="text-muted" style="font-size:12px;"> &mdash; ${escapeHtml(t.summary)}</span></span>
                <span class="toggle-switch"><input type="checkbox" data-tid="${escapeHtml(t.id)}" class="tech-enabled" ${checked}>
                    <span class="toggle-slider"></span></span>
            </label>
            <details style="margin-top:8px;">
                <summary class="text-muted" style="cursor:pointer;font-size:12px;">options (JSON)</summary>
                <textarea class="form-control form-control-mono tech-options" data-tid="${escapeHtml(t.id)}"
                    rows="${Math.min(10, Object.keys(options).length + 1)}" spellcheck="false"
                    style="margin-top:6px;">${escapeHtml(JSON.stringify(options, null, 2))}</textarea>
            </details>
        </div>`;
    }).join('');
}

/**
 * Assemble the edited techniques section and save the whole config.
 */
async function handleSave() {
    const result = document.getElementById('save-result');
    const techniques = {};
    for (const ta of document.querySelectorAll('.tech-options')) {
        const tid = ta.dataset.tid;
        let options;
        try {
            options = ta.value.trim() ? JSON.parse(ta.value) : {};
        } catch (err) {
            result.innerHTML = `<span style="color:var(--danger);">Invalid JSON for ${escapeHtml(tid)}: ${escapeHtml(err.message)}</span>`;
            return;
        }
        const enabled = document.querySelector(`.tech-enabled[data-tid="${tid}"]`).checked;
        techniques[tid] = { enabled, ...options };
    }
    currentConfig.techniques = techniques;
    const resp = await adminFetch('/api/admin/config', { method: 'PUT', body: currentConfig });
    if (resp.status) {
        result.innerHTML = `<span style="color:var(--success);">${escapeHtml(resp.message)}</span>`;
        notify('Saved', 'success');
    } else {
        const errs = (resp.data && resp.data.errors || []).map(escapeHtml).join('<br>');
        result.innerHTML = `<span style="color:var(--danger);">${escapeHtml(resp.message)}</span>${errs ? '<br>' + errs : ''}`;
    }
}

document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('save-btn').addEventListener('click', handleSave);
    loadTechniques();
});
