/* AI Tarpit Admin - Shared JavaScript utilities */

/**
 * Fetch JSON from an API endpoint.
 * Object bodies are serialized automatically.
 * @param {string} url
 * @param {object} options - fetch options
 * @returns {Promise<object>} the parsed API envelope
 */
async function apiFetch(url, options = {}) {
    const defaults = {
        headers: { 'Content-Type': 'application/json' },
    };
    const merged = { ...defaults, ...options };
    if (merged.body && typeof merged.body === 'object') {
        merged.body = JSON.stringify(merged.body);
    }
    const response = await fetch(url, merged);
    return response.json();
}

/**
 * Show a transient notification toast in the top-right corner.
 * @param {string} message
 * @param {'success'|'error'|'info'} type
 */
function notify(message, type = 'info') {
    const el = document.createElement('div');
    el.className = `notification ${type}`;
    el.textContent = message;
    document.body.appendChild(el);
    setTimeout(() => {
        el.style.opacity = '0';
        el.style.transition = 'opacity 0.3s';
        setTimeout(() => el.remove(), 300);
    }, 3000);
}

/**
 * Copy text to the clipboard and confirm with a notification.
 * @param {string} text
 */
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        notify('Copied to clipboard', 'success');
    }).catch(() => {
        notify('Failed to copy', 'error');
    });
}

/**
 * Escape HTML special characters for safe interpolation into innerHTML.
 * @param {string} str
 * @returns {string}
 */
function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

/**
 * Trigger a client-side file download.
 * @param {string|Blob} content
 * @param {string} filename
 * @param {string} mimeType
 */
function downloadFile(content, filename, mimeType = 'application/octet-stream') {
    const blob = content instanceof Blob ? content : new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
}

/**
 * Download an object as a pretty-printed JSON file.
 * @param {*} data
 * @param {string} filename
 */
function downloadJson(data, filename) {
    downloadFile(JSON.stringify(data, null, 2), filename, 'application/json');
}

/**
 * Format a byte count in human-readable form.
 * @param {number} bytes
 * @returns {string}
 */
function formatSize(bytes) {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

/**
 * Debounce a function call.
 * @param {Function} fn
 * @param {number} delay - milliseconds
 * @returns {Function}
 */
function debounce(fn, delay = 300) {
    let timer = null;
    return function (...args) {
        clearTimeout(timer);
        timer = setTimeout(() => fn.apply(this, args), delay);
    };
}
