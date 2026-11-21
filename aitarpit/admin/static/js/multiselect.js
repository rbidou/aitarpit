/* AI Tarpit Admin - Multi-select dropdown.
 *
 * A lightweight checkbox-popover control (the admin UI has no multiselect
 * elsewhere). The trigger button shows the label and how many options are
 * selected; the popover lists an "All" toggle plus one checkbox per option.
 * The selection is always an explicit set (every option checked by default),
 * so "deselect all" genuinely filters everything out rather than meaning "all".
 */

/**
 * Create a multi-select dropdown inside a mount element.
 * @param {HTMLElement} mountEl - empty container to render into
 * @param {object} opts
 * @param {string} opts.label - control label shown on the button
 * @param {Array<{value:string,label:string}>} opts.options - initial options
 * @param {function(string[]):void} [opts.onChange] - called with selected values
 * @returns {{getSelected:function():string[], setOptions:function(Array):void, isAll:function():boolean}}
 */
function createMultiSelect(mountEl, opts) {
    const state = { options: [], selected: new Set(), open: false };

    const root = document.createElement('div');
    root.className = 'ms';
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'ms-button form-control form-control-sm';
    const popover = document.createElement('div');
    popover.className = 'ms-popover';
    root.appendChild(button);
    root.appendChild(popover);
    mountEl.innerHTML = '';
    mountEl.appendChild(root);

    /**
     * Whether every option is currently selected.
     * @returns {boolean}
     */
    function isAll() {
        return state.options.length > 0 && state.selected.size === state.options.length;
    }

    /**
     * Current selection as an array of values (may be empty).
     * @returns {string[]}
     */
    function getSelected() {
        return state.options.filter(o => state.selected.has(o.value)).map(o => o.value);
    }

    /**
     * Repaint the trigger button text to reflect the current selection.
     */
    function paintButton() {
        const n = state.selected.size;
        const suffix = isAll() ? 'All' : n === 0 ? 'None' : `${n} selected`;
        button.innerHTML = `<span class="ms-label">${escapeHtml(opts.label)}</span>` +
            `<span class="ms-count">${escapeHtml(suffix)}</span><span class="ms-caret">&#9662;</span>`;
    }

    /**
     * Rebuild the popover's "All" toggle and option checkboxes.
     */
    function paintPopover() {
        const rows = state.options.map(o =>
            `<label class="ms-option"><input type="checkbox" data-value="${escapeHtml(o.value)}"` +
            `${state.selected.has(o.value) ? ' checked' : ''}><span>${escapeHtml(o.label)}</span></label>`).join('');
        popover.innerHTML =
            `<label class="ms-option ms-all"><input type="checkbox" data-all="1"${isAll() ? ' checked' : ''}>` +
            `<span>All</span></label><div class="ms-divider"></div>${rows}`;
    }

    /**
     * Notify the caller of the current selection.
     */
    function emit() {
        if (typeof opts.onChange === 'function') opts.onChange(getSelected());
    }

    /**
     * Replace the option list: unseen values start selected, prior choices persist.
     * @param {Array<{value:string,label:string}>} options
     */
    function setOptions(options) {
        const known = new Set(state.options.map(o => o.value));
        const next = new Set();
        options.forEach(o => {
            if (!known.has(o.value) || state.selected.has(o.value)) next.add(o.value);
        });
        state.options = options.slice();
        state.selected = next;
        paintButton();
        paintPopover();
    }

    /**
     * Open or close the popover.
     * @param {boolean} open
     */
    function toggle(open) {
        state.open = open;
        popover.classList.toggle('open', open);
        button.classList.toggle('active', open);
    }

    button.addEventListener('click', e => {
        e.stopPropagation();
        toggle(!state.open);
    });

    popover.addEventListener('change', e => {
        const input = e.target;
        if (input.dataset.all !== undefined) {
            state.selected = input.checked ? new Set(state.options.map(o => o.value)) : new Set();
        } else if (input.checked) {
            state.selected.add(input.dataset.value);
        } else {
            state.selected.delete(input.dataset.value);
        }
        paintButton();
        paintPopover();
        emit();
    });

    document.addEventListener('click', e => {
        if (state.open && !root.contains(e.target)) toggle(false);
    });

    setOptions(opts.options || []);
    return { getSelected, setOptions, isAll };
}
