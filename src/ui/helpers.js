import { t } from '../i18n/index.js';

export const BUSY_PHASES = Object.freeze(['scanning', 'staging', 'restoring', 'purging']);

const ESCAPES = Object.freeze({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' });

export function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => ESCAPES[character]);
}

export function art(name, className = '') {
  return `<svg class="${className}" aria-hidden="true"><use href="./assets/art.svg#${name}"></use></svg>`;
}

export function icon(name) {
  const paths = {
    arrow: '<path d="M4 12h15m-6-6 6 6-6 6"/>',
    reset: '<path d="M5 8a8 8 0 1 1-1 7M5 3v6h6"/>',
    copy: '<rect x="8" y="8" width="12" height="13" rx="2"/><path d="M15 8V3H3v12h5"/>',
    home: '<path d="m3 10 9-7 9 7M5 9v12h14V9M9 21v-8h6v8"/>',
    check: '<path d="m5 12 4 4 10-10"/>',
    close: '<path d="m6 6 12 12M18 6 6 18"/>',
    external: '<path d="M13 4h7v7m0-7L9 15M9 4H4v16h16v-5"/>',
    history: '<path d="M4 8a9 9 0 1 1-1 7M4 3v6h6m2-3v7l4 2"/>',
    sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M2 12h2m16 0h2M5 5l1.5 1.5m11 11L19 19M5 19l1.5-1.5m11-11L19 5"/>',
    moon: '<path d="M20 15.5A9 9 0 0 1 8.5 4 9 9 0 1 0 20 15.5Z"/>',
    chevron: '<path d="m7 9.5 5 5 5-5"/>',
  };
  if (!Object.hasOwn(paths, name)) throw new Error(`Unknown icon: ${name}`);
  return `<svg class="ui-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">${paths[name]}</svg>`;
}

export function button(options) {
  const { action, label, kind = 'primary', disabled = false, id = '', primary = false, pressed } = options;
  const pressedAttribute = pressed === undefined ? '' : `aria-pressed="${pressed}"`;
  return `<button class="button button-${kind}" data-action="${action}" data-id="${id}"
    data-focus-key="${action}-${id}" ${primary ? 'data-primary' : ''} ${pressedAttribute}
    ${disabled ? 'disabled' : ''}>${label}</button>`;
}

export function stepIndex(phase) {
  const steps = {
    welcome: 0, scanning: 0, inspect: 1, preview: 2,
    staging: 3, staged: 3, restoring: 3, purging: 4, complete: 4,
  };
  if (!Object.hasOwn(steps, phase)) throw new Error(`Unknown phase: ${phase}`);
  return steps[phase];
}

export function stepLabel(phase) {
  return t(['Explore', 'Choose', 'Preview', 'Stage', 'Make room'][stepIndex(phase)]);
}

export function isBusy(state) {
  return BUSY_PHASES.includes(state.phase);
}
