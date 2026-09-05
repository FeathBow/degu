import { currentCommand } from '../commands.js';
import { formatSize, locationById, quotaFor, totalSize } from '../scenario.js';
import { button, escapeHtml, icon, isBusy, stepIndex } from './helpers.js';
import { t } from '../i18n/index.js';

const PERCENT_SCALE = 100;

export function quotaPanel(scenario, state) {
  const quota = quotaFor(scenario, state);
  const percentage = quota.usedMiB / scenario.capacityMiB * PERCENT_SCALE;
  const goalDone = quota.removedMiB >= scenario.goalMiB;
  return `<div class="quota-heading"><span>${icon('home')} ${t('HOME quota')}</span>
    <span class="quota-value"><strong data-quota-used>${formatSize(quota.usedMiB)}</strong> / ${formatSize(scenario.capacityMiB)}</span></div>
    <div class="quota-track" role="progressbar" aria-label="${t('HOME quota used')}"
      aria-valuemin="0" aria-valuemax="${scenario.capacityMiB}" aria-valuenow="${quota.usedMiB}">
      <div class="quota-fill ${goalDone ? 'has-room' : ''}" style="width:${percentage}%"></div></div>
    <div class="quota-caption"><span data-quota-caption>${t(goalDone ? 'A little breathing room.' : 'Getting a little crowded in here.')}</span>
      <span data-quota-free>${t('{size} available', { size: formatSize(quota.freeMiB) })}</span></div>`;
}

export function renderQuota(root, scenario, state) {
  if (!root.firstElementChild) root.innerHTML = quotaPanel(scenario, state);
  const quota = quotaFor(scenario, state);
  const goalDone = quota.removedMiB >= scenario.goalMiB;
  root.querySelector('[data-quota-used]').textContent = formatSize(quota.usedMiB);
  root.querySelector('[data-quota-free]').textContent = t('{size} available', { size: formatSize(quota.freeMiB) });
  root.querySelector('[data-quota-caption]').textContent = t(goalDone ? 'A little breathing room.' : 'Getting a little crowded in here.');
  root.querySelector('[role="progressbar"]').setAttribute('aria-valuenow', quota.usedMiB);
  const fill = root.querySelector('.quota-fill');
  fill.style.width = `${quota.usedMiB / scenario.capacityMiB * PERCENT_SCALE}%`;
  fill.classList.toggle('has-room', goalDone);
}

export function journey(state) {
  const active = stepIndex(state.phase);
  return `<ol class="journey-list" aria-label="${t('Tutorial progress')}">${['Explore', 'Choose', 'Preview', 'Stage', 'Make room']
    .map((label, index) => `<li class="${index === active ? 'current' : ''} ${index < active ? 'passed' : ''}"
      ${index === active ? 'aria-current="step"' : ''}><span class="journey-dot">${index < active ? '✓' : index + 1}</span>
      <span>${t(label)}</span></li>`).join('')}</ol>`;
}

export function planList(scenario, ids) {
  return `<ul class="plan-list">${ids.map((id) => {
    const item = locationById(scenario, id);
    return `<li><div><strong>${t(item.name)}</strong><span>${formatSize(item.sizeMiB)}</span></div>
      <code>${escapeHtml(item.path)}</code></li>`;
  }).join('')}</ul>`;
}

export function terminal(scenario, state) {
  const command = currentCommand(scenario, state);
  return terminalFrame({ command, caption: terminalCaption(scenario, state) });
}

export function terminalFrame(options) {
  const { command, caption, output = '' } = options;
  return `<div class="terminal-header"><span><i></i> ${t('The command behind the story')}</span>
    <button class="terminal-copy" data-action="copy" data-focus-key="copy" aria-label="${t('Copy the displayed command')}">${icon('copy')} ${t('Copy')}</button></div>
    <div class="terminal-body"><div class="command-line"><span class="prompt">$</span>
    <code data-command>${escapeHtml(command)}</code></div>
    ${output ? `<pre class="terminal-output">${escapeHtml(output)}</pre>` : ''}
    <p class="terminal-caption">${caption}</p></div>
    <div class="terminal-bottom"><span>${t('Commands shown here are examples. No real command is executed.')}</span>
    <span id="copy-feedback" role="status"></span></div>`;
}

function terminalCaption(scenario, state) {
  const count = state.visitedIds.length;
  if (state.phase === 'welcome') return t('A read-only look around. Every good plan starts here.');
  if (state.phase === 'scanning') return t('Exploring known locations… {count} / {total} visited', { count, total: scenario.locations.length });
  if (state.phase === 'staged') return t('{size} staged · quota unchanged · undo available', { size: formatSize(totalSize(scenario, state.trashIds)) });
  if (state.phase === 'complete') return t('{size} removed in this demo · checkpoint preserved', { size: formatSize(quotaFor(scenario, state).removedMiB) });
  if (state.phase === 'restoring') return t('Restoring the staged cache to its original location…');
  if (state.phase === 'purging') return t('Permanently removing only the confirmed staged locations…');
  if (state.phase === 'staging') return t('Checking the exact plan and moving caches into same-filesystem trash…');
  return t(state.notice || 'Preview the exact selection before making a change.');
}

export function activityLink(state) {
  return `${button({ action: 'openReceipt', kind: 'secondary', label: `${icon('history')} ${t('Demo activity')}`, disabled: isBusy(state) })}
    <span class="activity-count">${t(state.activity.length === 1 ? '{count} entry' : '{count} entries', { count: state.activity.length })}</span>`;
}
