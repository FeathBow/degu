import { formatSize, totalSize } from '../scenario.js';
import { escapeHtml, icon } from './helpers.js';
import { planList } from './components.js';
import { t } from '../i18n/index.js';

export function createDialogs(options) {
  const { root, scenario, dispatch } = options;
  let active = null;
  let locale = document.documentElement.lang;
  return (state) => {
    if (!state.dialog && !active) { locale = document.documentElement.lang; return; }
    if (state.dialog === active && locale === document.documentElement.lang) return;
    const confirmation = root.querySelector('#purge-confirmation')?.value;
    locale = document.documentElement.lang;
    const closed = active;
    root.querySelector('dialog')?.close();
    root.replaceChildren();
    active = state.dialog;
    if (!active) {
      const action = closed === 'purge' ? 'requestPurge' : 'openReceipt';
      document.querySelector(`#app [data-action="${action}"]:not(:disabled)`)?.focus({ preventScroll: true });
      return;
    }
    root.innerHTML = active === 'purge' ? purgeDialog(scenario, state) : receiptDialog(state);
    const dialog = root.querySelector('dialog');
    dialog.addEventListener('cancel', (event) => { event.preventDefault(); dispatch('closeDialog'); });
    dialog.showModal();
    if (confirmation !== undefined && active === 'purge') {
      root.querySelector('#purge-confirmation').value = confirmation;
      root.querySelector('#purge-submit').disabled = confirmation !== 'purge';
    }
  };
}

function dialogHeader(label) {
  return `<div class="dialog-heading"><span class="eyebrow">${t(label)}</span>
    <button class="icon-button" data-action="closeDialog" aria-label="${t('Close dialog')}">${icon('close')}</button></div>`;
}

function purgeDialog(scenario, state) {
  return `<dialog class="dialog purge-dialog" aria-labelledby="dialog-title" aria-describedby="purge-description">
    ${dialogHeader('ONE LAST LOOK')}<h2 id="dialog-title">${t('A permanent goodbye.')}</h2>
    <p id="purge-description">${t('Remove {size} from the undo nook. These are the exact caches you staged. This step cannot be undone.', { size: formatSize(totalSize(scenario, state.trashIds)) })}</p>
    ${planList(scenario, state.trashIds)}
    <div class="purge-warning">${t('Your checkpoint is outside this plan and will stay untouched.')}</div>
    <form id="purge-form"><label for="purge-confirmation">${t('Type <strong>purge</strong> to confirm this demo step')}</label>
      <input id="purge-confirmation" name="confirmation" autocomplete="off" autocapitalize="none" spellcheck="false"
        placeholder="purge" aria-describedby="purge-simulation" autofocus>
      <p id="purge-simulation" class="lesson-soft">${t('Browser simulation. No files on your machine will change.')}</p>
      <div class="dialog-actions"><button class="button button-secondary" type="button" data-action="closeDialog">${t('Keep in the nook')}</button>
        <button class="button button-danger" type="submit" id="purge-submit" disabled>${t('Remove permanently')}</button></div></form></dialog>`;
}

function receiptDialog(state) {
  return `<dialog class="dialog receipt-dialog" aria-labelledby="dialog-title">
    ${dialogHeader('DEMO ACTIVITY')}<h2 id="dialog-title">${t('A story you can check.')}</h2>
    <p>${t('Each recorded step names the exact paths and the corresponding command.')}</p>
    <div class="receipt-disclaimer"><strong>${t('SIMULATED · NOT A REAL AUDIT LOG')}</strong>
      <span>${t('This receipt describes your browser lesson. No degu command was executed.')}</span></div>
    <ol class="receipt-list">${state.activity.length ? state.activity.map(receiptEntry).join('')
      : `<li class="receipt-empty">${t('No plan or file operation yet. Explore a cache to begin.')}</li>`}</ol>
    <div class="dialog-actions"><button class="button button-secondary" data-action="closeDialog">${t('Back to the story')}</button>
      <button class="button button-primary" data-action="download">${t('Download demo JSON')} ${icon('arrow')}</button></div></dialog>`;
}

function receiptEntry(entry) {
  return `<li><div class="receipt-entry-heading"><strong>${t(entry.action)}</strong><span>${entry.id} · ${formatSize(entry.sizeMiB)}</span></div>
    <code>${escapeHtml(entry.command)}</code><ul>${entry.paths.map((path) => `<li>${escapeHtml(path)}</li>`).join('')}</ul>
    <time datetime="${escapeHtml(entry.at)}">${escapeHtml(entry.at)}</time></li>`;
}
