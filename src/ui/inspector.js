import { formatSize, locationById, quotaFor, totalSize } from '../scenario.js';
import { art, button, escapeHtml, icon } from './helpers.js';
import { planList } from './components.js';
import { t } from '../i18n/index.js';

export function inspector(scenario, state) {
  const views = {
    welcome, scanning: busy, inspect: inspectLocation, preview,
    staging: busy, staged, restoring: busy, purging: busy, complete,
  };
  return views[state.phase](scenario, state);
}

function heading(number, label) {
  return `<div class="lesson-eyebrow"><span class="lesson-number">${number}</span>${t(label)}</div>`;
}

function welcome(scenario) {
  return `${heading('01', 'A SMALL MISSION')}
    <h2>${t('Big ideas need<br> a little room.')}</h2>
    <p>${t('Your HOME is almost full. Meet degu, your curious little cache guide.')}</p>
    <div class="mission-card"><span class="mission-leaf">${art('leaf')}</span>
      <div><strong>${t('Make {size} of room', { size: formatSize(scenario.goalMiB) })}</strong><span>${t('Keep your experiment checkpoint safe.')}</span></div></div>
    <p class="lesson-soft">${t('Explore the room together. Find out what can go, what deserves a second look, and what stays.')}</p>
    <div class="lesson-actions">${button({ action: 'scan', label: `${t('Let’s explore')} ${icon('arrow')}`, primary: true })}</div>
    <div class="lesson-footnote"><span>${t('~2 minutes')}</span><i></i><span>${t('No installation')}</span></div>`;
}

function inspectLocation(scenario, state) {
  const item = locationById(scenario, state.focusId);
  const selected = state.selectedIds.includes(item.id);
  return `${locationChoices(scenario, state)}${heading('02', 'GET TO KNOW YOUR CACHE')}
    <div class="lesson-title-row"><h2>${t(item.name)}</h2><span class="size-tag">${formatSize(item.sizeMiB)}</span></div>
    <span class="status-badge ${item.disposition}">${t(item.label)}</span>
    <p>${t(item.why)}</p>
    <div class="consequence ${item.disposition}"><strong>${t(item.disposition === 'report_only' ? 'Your research stays' : 'What to expect')}</strong><p>${t(item.consequence)}</p></div>
    <details class="path-details"><summary>${t('See the exact path')}</summary><code>${escapeHtml(item.path)}</code></details>
    <div class="lesson-actions">${selectionButton(item, state, selected)}
      ${button({ action: 'preview', label: `${previewLabel(state.selectedIds.length)} ${icon('arrow')}`,
        disabled: !state.selectedIds.length, primary: state.selectedIds.length > 0 })}</div>
    <p class="selection-hint">${state.selectedIds.length ? t('{size} selected. Nothing has changed yet.', { size: formatSize(totalSize(scenario, state.selectedIds)) }) : t(item.hint)}</p>
    ${state.notice ? `<p class="notice">${t(state.notice)}</p>` : ''}`;
}

function previewLabel(count) {
  if (!count) return t('Preview selected caches');
  return t(count === 1 ? 'Preview {count} cache' : 'Preview {count} caches', { count });
}

function locationChoices(scenario, state) {
  return `<nav class="location-choices" aria-label="${t('Choose a location to inspect')}">${scenario.locations.map((item) =>
    `<button data-action="inspect" data-id="${item.id}" data-focus-key="choice-${item.id}"
      aria-pressed="${state.focusId === item.id}">${t(item.id === 'pip' ? 'Packages' : item.id === 'models' ? 'Models' : 'Your work')}</button>`).join('')}</nav>`;
}

function selectionButton(item, state, selected) {
  if (item.disposition === 'report_only') {
    return button({ action: 'select', id: item.id, kind: 'secondary', disabled: true, label: `${icon('check')} ${t('Kept out of cleanup')}` });
  }
  if (item.disposition === 'opt_in' && !state.reviewedIds.includes(item.id)) {
    return button({ action: 'review', id: item.id, kind: 'secondary', label: t('Include this cache after review') });
  }
  return button({ action: 'select', id: item.id, kind: 'secondary', pressed: selected,
    label: selected ? `${icon('check')} ${t('Selected · click to remove')}` : t('Select this cache'), primary: !state.selectedIds.length });
}

function preview(scenario, state) {
  const size = formatSize(totalSize(scenario, state.planIds));
  return `${heading('03', 'LOOK BEFORE YOU MOVE')}
    <h2>${t('A plan you<br> can check.')}</h2>
    <p>${t('Only these exact locations will move into degu’s undo nook.')}</p>
    ${planList(scenario, state.planIds)}
    <div class="impact-grid"><div><span>${t('To be staged')}</span><strong>${size}</strong></div>
      <div><span>${t('Quota released')}</span><strong>0 GiB</strong></div></div>
    <p class="lesson-soft">${t('The nook is inside HOME. Moving a cache there keeps it recoverable and still counts against quota.')}</p>
    <div class="lesson-actions">${button({ action: 'stage', label: `${t('Move to undo nook')} ${icon('arrow')}`, primary: true })}
      ${button({ action: 'back', kind: 'secondary', label: t('Change selection') })}</div>`;
}

function busy(scenario, state) {
  const descriptions = {
    scanning: ['01', 'FOLLOWING OUR NOSE', 'A little look around.', 'Finding known caches and the things that should stay.'],
    staging: ['04', 'A CAREFUL LITTLE MOVE', 'Making it reversible.', 'Checking the selected caches before moving them into the undo nook.'],
    restoring: ['04', 'BACK WHERE IT BELONGS', 'Putting things back.', 'Restoring the staged caches to their original paths.'],
    purging: ['05', 'ONLY WHAT YOU CONFIRMED', 'Making real room.', 'Permanently removing the reviewed contents of the undo nook.'],
  };
  const [number, label, title, description] = descriptions[state.phase];
  return `${heading(number, label)}<h2>${t(title)}</h2><p>${t(description)}</p>
    <div class="busy-state"><span class="spinner" aria-hidden="true"></span>
      <div><strong>${t(state.busyId ? locationById(scenario, state.busyId).name : 'degu is on the move')}</strong>
      <span>${t('This is an animated browser simulation.')}</span></div></div>
    ${busyProgress(scenario, state)}
    <div class="quiet-note">${icon('check')} ${t('Your checkpoint stays untouched.')}</div>`;
}

function busyProgress(scenario, state) {
  if (state.phase === 'restoring') return `<p class="lesson-soft">${t('Quota usage stays the same while restoring.')}</p>`;
  const isScan = state.phase === 'scanning';
  const total = isScan ? scenario.locations.length : state.planIds.length;
  const done = isScan ? state.visitedIds.length
    : state.phase === 'staging' ? state.trashIds.length : state.purgedIds.length;
  const label = t(isScan ? 'Locations explored' : state.phase === 'staging' ? 'Caches staged' : 'Caches removed');
  return `<div class="task-progress"><div><span>${label}</span><strong>${done} / ${total}</strong></div>
    <progress max="${total}" value="${done}" aria-label="${label}"></progress></div>`;
}

function staged(scenario, state) {
  const size = formatSize(totalSize(scenario, state.trashIds));
  return `${heading('04', 'A MOVE WORTH UNDERSTANDING')}
    <h2>${t('Still in<br> your HOME.')}</h2>
    <p>${t('degu moved {size} into the undo nook. Your quota is exactly where it started.', { size })}</p>
    <div class="lesson-revelation"><span class="revelation-icon">↔</span>
      <div><strong>${t('Moved ≠ freed')}</strong><p>${t('The nook uses the same filesystem. Those files still take up space.')}</p></div></div>
    <p class="lesson-soft">${t('Try restoring them, or review a permanent cleanup to finish making room.')}</p>
    <div class="lesson-actions">${button({ action: 'requestPurge', label: `${t('Review permanent cleanup')} ${icon('arrow')}`, primary: true })}
      ${button({ action: 'undo', kind: 'secondary', label: `${icon('reset')} ${t('Try undo')}` })}</div>
    <p class="selection-hint">${t('Your next choice decides what happens to the staged files.')}</p>`;
}

function complete(scenario, state) {
  const quota = quotaFor(scenario, state);
  const goalDone = quota.removedMiB >= scenario.goalMiB;
  return `${heading('05', goalDone ? 'MISSION COMPLETE' : 'CLEANUP COMPLETE')}
    <h2>${t('Room for<br> what’s next.')}</h2>
    <div class="success-number">${formatSize(quota.removedMiB)}<span>${t('removed in this demo')}</span></div>
    <div class="success-facts"><p>${icon('check')} ${t('{size} now available in HOME', { size: formatSize(quota.freeMiB) })}</p>
      <p>${icon('check')} ${t('Your experiment checkpoint is preserved')}</p>
      <p>${icon('check')} ${t('Every step is in the demo activity')}</p></div>
    ${state.purgedIds.includes('models') ? `<p class="notice amber">${t('The model cache was removed. Download it again before its next use.')}</p>` : ''}
    <p class="lesson-soft">${t('These caches were permanently removed. Undo is no longer available for them.')}</p>
    <div class="lesson-actions"><a class="button button-primary" href="https://github.com/FeathBow/degu#installation" target="_blank" rel="noopener noreferrer">${t('Try degu on your machine')} ${icon('external')}</a>
      ${button({ action: 'openReceipt', kind: 'secondary', label: t('See the demo receipt'), primary: true })}</div>
    <button class="text-button" data-action="reset" data-focus-key="restart-complete">${t('Restart the demo')}</button>`;
}
