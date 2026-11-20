/* AI Tarpit Admin - Reports */

const EXT = { text: 'txt', json: 'json', csv: 'csv', html: 'html' };
const MIME = { text: 'text/plain', json: 'application/json', csv: 'text/csv', html: 'text/html' };
let lastContent = '';
let lastFormat = 'text';

/**
 * Request a report in the chosen format and show it.
 */
async function handleGenerate() {
    const fmt = document.getElementById('report-format').value;
    const hours = parseFloat(document.getElementById('report-hours').value);
    const body = { format: fmt };
    if (!Number.isNaN(hours) && hours > 0) body.since = Date.now() / 1000 - hours * 3600;

    const resp = await adminFetch('/api/admin/report', { method: 'POST', body });
    if (!resp.status) {
        document.getElementById('error-message').textContent = resp.message || 'Report failed';
        showSection('error');
        return;
    }
    lastFormat = fmt;
    lastContent = fmt === 'json' ? JSON.stringify(resp.data.report, null, 2) : resp.data.rendered;
    document.getElementById('report-output').textContent = lastContent;
    showSection('results');
}

document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('generate-btn').addEventListener('click', handleGenerate);
    document.getElementById('copy-btn').addEventListener('click', () => copyToClipboard(lastContent));
    document.getElementById('download-btn').addEventListener('click', () =>
        downloadFile(lastContent, `aitarpit-report.${EXT[lastFormat]}`, MIME[lastFormat]));
});
