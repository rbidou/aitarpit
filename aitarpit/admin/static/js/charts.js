/* AI Tarpit Admin - Dependency-free SVG charts.
 *
 * The admin UI is an offline, loopback-only surface that bundles no charting
 * library, so these helpers draw pie, stacked-bar and stacked-area charts as
 * inline SVG. Each renders into a container element; series carry their own
 * colours (resolved by the caller) while axes, gridlines and text use theme
 * ink tokens via CSS classes (never the series colour), per the dataviz rules.
 */

/** SVG namespace for element creation. */
const SVG_NS = 'http://www.w3.org/2000/svg';

/**
 * Format an integer with thousands separators.
 * @param {number} n
 * @returns {string}
 */
function fmtNum(n) {
    return Math.round(n).toLocaleString();
}

/**
 * Round a value up to a readable axis maximum (1/2/5 x 10^k).
 * @param {number} value
 * @returns {number}
 */
function niceMax(value) {
    if (value <= 0) return 1;
    const pow = Math.pow(10, Math.floor(Math.log10(value)));
    const frac = value / pow;
    const step = frac <= 1 ? 1 : frac <= 2 ? 2 : frac <= 5 ? 5 : 10;
    return step * pow;
}

/**
 * Render a standard empty-state message into a container.
 * @param {HTMLElement} el
 * @param {string} message
 */
function renderEmptyChart(el, message) {
    el.innerHTML = `<div class="empty-state"><p>${message}</p></div>`;
}

/**
 * Build a legend list (coloured swatch + label + optional value).
 * @param {Array<{label:string,color:string,value?:number}>} items
 * @returns {string} HTML for a <ul class="chart-legend">
 */
function legendHtml(items) {
    const rows = items.map(i =>
        `<li><span class="chart-swatch" style="background:${i.color}"></span>` +
        `<span class="chart-legend-label">${escapeHtml(i.label)}</span>` +
        (i.value === undefined ? '' : `<span class="chart-legend-value">${fmtNum(i.value)}</span>`) +
        `</li>`).join('');
    return `<ul class="chart-legend">${rows}</ul>`;
}

/**
 * Compute cumulative stack tops for a row of values.
 * @param {object} values - map seriesKey -> number
 * @param {Array<{key:string}>} seriesDefs
 * @returns {{total:number, tops:number[]}} running tops aligned to seriesDefs
 */
function stackRow(values, seriesDefs) {
    let acc = 0;
    const tops = seriesDefs.map(s => {
        acc += values[s.key] || 0;
        return acc;
    });
    return { total: acc, tops };
}

/**
 * Render a vertical stacked bar chart (one bar per category).
 * @param {HTMLElement} el - container
 * @param {Array<{label:string,values:object}>} categories
 * @param {Array<{key:string,label:string,color:string}>} seriesDefs
 */
function renderStackedBar(el, categories, seriesDefs) {
    const cats = categories.filter(c => stackRow(c.values, seriesDefs).total > 0);
    if (!cats.length) {
        renderEmptyChart(el, 'No events in this view');
        return;
    }
    const W = 720, H = 300, m = { top: 16, right: 12, bottom: 54, left: 44 };
    const plotW = W - m.left - m.right, plotH = H - m.top - m.bottom;
    const maxTotal = niceMax(Math.max(...cats.map(c => stackRow(c.values, seriesDefs).total)));
    const y = v => m.top + plotH - (v / maxTotal) * plotH;
    const band = plotW / cats.length;
    const barW = Math.min(46, band * 0.62);

    const ticks = 4;
    let grid = '';
    for (let i = 0; i <= ticks; i++) {
        const gv = (maxTotal / ticks) * i;
        const gy = y(gv);
        grid += `<line x1="${m.left}" y1="${gy}" x2="${W - m.right}" y2="${gy}" class="chart-grid"></line>` +
                `<text x="${m.left - 8}" y="${gy + 4}" class="chart-label chart-label-right">${fmtNum(gv)}</text>`;
    }

    let bars = '';
    cats.forEach((c, i) => {
        const cxBar = m.left + band * i + band / 2;
        const x = cxBar - barW / 2;
        const { tops } = stackRow(c.values, seriesDefs);
        let prevTop = 0;
        seriesDefs.forEach((s, si) => {
            const v = c.values[s.key] || 0;
            if (v <= 0) { prevTop = tops[si]; return; }
            const yTop = y(tops[si]);
            const yBase = y(prevTop);
            const h = Math.max(0, yBase - yTop - 2); // 2px surface gap between segments
            bars += `<rect x="${x}" y="${yTop}" width="${barW}" height="${h}" rx="2" fill="${s.color}" class="chart-seg">` +
                    `<title>${escapeHtml(c.label)} - ${escapeHtml(s.label)}: ${fmtNum(v)}</title></rect>`;
            prevTop = tops[si];
        });
        bars += `<text x="${cxBar}" y="${H - m.bottom + 16}" class="chart-label chart-label-mid" ` +
                `transform="rotate(35 ${cxBar} ${H - m.bottom + 16})">${escapeHtml(c.label)}</text>`;
    });

    const axis = `<line x1="${m.left}" y1="${m.top}" x2="${m.left}" y2="${m.top + plotH}" class="chart-axis"></line>` +
                 `<line x1="${m.left}" y1="${m.top + plotH}" x2="${W - m.right}" y2="${m.top + plotH}" class="chart-axis"></line>`;
    const legend = legendHtml(seriesDefs.map(s => ({ label: s.label, color: s.color })));
    el.innerHTML =
        `<svg viewBox="0 0 ${W} ${H}" class="chart-svg" role="img">${grid}${bars}${axis}</svg>${legend}`;
}

/**
 * Render a stacked area chart over ordered time buckets.
 * @param {HTMLElement} el - container
 * @param {Array<{label:string,values:object}>} buckets - chronological
 * @param {Array<{key:string,label:string,color:string}>} seriesDefs
 */
function renderStackedArea(el, buckets, seriesDefs) {
    const anyData = buckets.some(b => stackRow(b.values, seriesDefs).total > 0);
    if (buckets.length < 2 || !anyData) {
        renderEmptyChart(el, 'Not enough events over time to plot');
        return;
    }
    const W = 720, H = 300, m = { top: 16, right: 12, bottom: 42, left: 44 };
    const plotW = W - m.left - m.right, plotH = H - m.top - m.bottom;
    const maxTotal = niceMax(Math.max(...buckets.map(b => stackRow(b.values, seriesDefs).total), 1));
    const n = buckets.length;
    const x = i => m.left + (plotW * i) / (n - 1);
    const y = v => m.top + plotH - (v / maxTotal) * plotH;

    const ticks = 4;
    let grid = '';
    for (let i = 0; i <= ticks; i++) {
        const gv = (maxTotal / ticks) * i;
        const gy = y(gv);
        grid += `<line x1="${m.left}" y1="${gy}" x2="${W - m.right}" y2="${gy}" class="chart-grid"></line>` +
                `<text x="${m.left - 8}" y="${gy + 4}" class="chart-label chart-label-right">${fmtNum(gv)}</text>`;
    }

    // Cumulative tops per bucket, aligned to seriesDefs.
    const rows = buckets.map(b => stackRow(b.values, seriesDefs).tops);
    let areas = '';
    seriesDefs.forEach((s, si) => {
        const topPts = rows.map((tops, i) => `${x(i)} ${y(tops[si])}`);
        const botPts = rows.map((tops, i) => `${x(i)} ${y(si === 0 ? 0 : tops[si - 1])}`).reverse();
        areas += `<polygon points="${topPts.concat(botPts).join(' ')}" fill="${s.color}" ` +
                 `class="chart-area"><title>${escapeHtml(s.label)}</title></polygon>`;
    });

    // X labels: first, last and a few in between to avoid collisions.
    const every = Math.max(1, Math.ceil(n / 8));
    let xlabels = '';
    buckets.forEach((b, i) => {
        if (i % every !== 0 && i !== n - 1) return;
        xlabels += `<text x="${x(i)}" y="${H - m.bottom + 18}" class="chart-label chart-label-mid">${escapeHtml(b.label)}</text>`;
    });

    const axis = `<line x1="${m.left}" y1="${m.top}" x2="${m.left}" y2="${m.top + plotH}" class="chart-axis"></line>` +
                 `<line x1="${m.left}" y1="${m.top + plotH}" x2="${W - m.right}" y2="${m.top + plotH}" class="chart-axis"></line>`;
    const legend = legendHtml(seriesDefs.map(s => ({ label: s.label, color: s.color })));
    el.innerHTML =
        `<svg viewBox="0 0 ${W} ${H}" class="chart-svg" role="img">${grid}${areas}${xlabels}${axis}</svg>${legend}`;
}
