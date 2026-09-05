import { formatSize, locationById, totalSize } from '../scenario.js';
import { art, button, icon, isBusy } from './helpers.js';
import { t } from '../i18n/index.js';

const RESTING_POSITION = Object.freeze({ x: 45, y: 71 });
const NOOK_POSITION = Object.freeze({ x: 38, y: 77 });
const PICKUP_POSITIONS = Object.freeze({ pip: { x: 32, y: 59 }, models: { x: 62, y: 50 } });
const GUIDE_POSITIONS = Object.freeze({
  pip: { x: 45, y: 65 }, models: { x: 51, y: 61 }, checkpoint: { x: 51, y: 84 },
});

export function sceneShell(scenario) {
  return `<section class="scene-card" aria-label="${t('Your simulated HOME')}">
    <div class="scene-topline"><span class="scene-title">${icon('home')} ${scenario.home}</span>
      <span class="scene-mode">${t('A LITTLE WORLD · DEMO')}</span></div>
    <div class="room">
      <div class="room-window" aria-hidden="true"><i class="window-sun"></i><i class="window-hill"></i>
        <i class="window-hill second"></i><i class="window-bars"></i></div>
      <div class="room-frame" aria-hidden="true">${art('leaf')}</div>
      ${art('plant', 'room-plant')}<span class="room-label" aria-hidden="true">${t('HOME SWEET HOME')}</span>
      <svg class="room-route" viewBox="0 0 600 390" preserveAspectRatio="none" aria-hidden="true">
        <path d="M138 190 Q215 105 432 145 Q510 190 450 295 Q305 350 108 316"/></svg>
      <div data-map-nodes>${scenario.locations.map(mapNode).join('')}</div>
      <div class="undo-nook">${art('basket')}<span class="nook-title">${t('The undo nook')}</span>
        <span class="nook-meta" data-nook-meta>${t('Still inside HOME')}</span><span class="nook-count" data-nook-count hidden></span></div>
      <div class="mascot" data-mascot><div class="mascot-bubble" data-bubble></div>
        ${art('degu', 'mascot-art')}<span class="carried-cache" aria-hidden="true">${art('packages')}</span></div>
    </div>
    <div class="scene-bottomline"><p data-scene-hint>${t('A tiny adventure. A useful habit.')}</p>
      <span class="scene-keys">${t('<kbd>Tab</kbd> to explore · <kbd>Enter</kbd> to act')}</span>
      <div class="scene-mobile-start"><p>${t('Make 2 GiB of room. Keep your checkpoint.')}</p>
        ${button({ action: 'scan', label: `${t('Let’s explore')} ${icon('arrow')}` })}</div></div>
  </section>`;
}

function mapNode(item) {
  return `<button class="map-node" data-action="inspect" data-id="${item.id}" data-kind="${item.disposition}"
    data-focus-key="map-${item.id}" style="left:${item.position.x}%;top:${item.position.y}%"
    aria-label="${t('Inspect {name}', { name: t(item.name) })}">${art(item.symbol, 'node-art')}
    <span class="node-title">${t(item.name)}</span><span class="node-meta" data-node-meta></span>
    <span class="node-status" data-node-status></span></button>`;
}

export function renderScene(root, scenario, state) {
  for (const item of scenario.locations) updateNode(root, item, state);
  const mascot = root.querySelector('[data-mascot]');
  const position = guidePosition(state);
  mascot.style.left = `${position.x}%`;
  mascot.style.top = `${position.y}%`;
  mascot.classList.toggle('is-moving', isBusy(state));
  mascot.classList.toggle('is-carrying', Boolean(state.carryingId));
  if (state.carryingId) mascot.querySelector('.carried-cache').innerHTML = art(locationById(scenario, state.carryingId).symbol);
  mascot.classList.toggle('is-celebrating', state.phase === 'complete');
  root.querySelector('[data-bubble]').innerHTML = t(bubble(state));
  const count = root.querySelector('[data-nook-count]');
  count.hidden = state.trashIds.length === 0;
  count.textContent = state.trashIds.length;
  root.querySelector('[data-nook-meta]').textContent = state.trashIds.length
    ? t('{size} · still uses quota', { size: formatSize(totalSize(scenario, state.trashIds)) }) : t('Still inside HOME');
  root.querySelector('[data-scene-hint]').textContent = t(state.phase === 'inspect'
    ? 'Click a cache to learn what happens to it.' : 'Sample files. Nothing on your machine changes.');
}

function updateNode(root, item, state) {
  const node = root.querySelector(`.map-node[data-id="${item.id}"]`);
  const discovered = state.visitedIds.includes(item.id);
  const staged = state.trashIds.includes(item.id);
  const purged = state.purgedIds.includes(item.id);
  node.disabled = state.phase !== 'inspect';
  node.classList.toggle('is-focused', discovered && state.focusId === item.id && state.phase === 'inspect');
  node.classList.toggle('is-selected', state.selectedIds.includes(item.id) && !staged && !purged);
  node.classList.toggle('is-undiscovered', !discovered);
  node.classList.toggle('is-away', staged || purged);
  node.querySelector('[data-node-meta]').textContent = discovered ? formatSize(item.sizeMiB) : t('Waiting to explore');
  node.querySelector('[data-node-status]').textContent = t(purged ? 'Removed in demo'
    : staged ? 'In the undo nook' : discovered ? item.label : item.source);
}

function guidePosition(state) {
  if (state.phase === 'staging' && !state.carryingId && !state.trashIds.includes(state.busyId)) return PICKUP_POSITIONS[state.busyId];
  if (['staged', 'staging', 'purging'].includes(state.phase)) return NOOK_POSITION;
  if (['welcome', 'complete'].includes(state.phase)) return RESTING_POSITION;
  return GUIDE_POSITIONS[state.focusId];
}

function bubble(state) {
  const lines = {
    welcome: 'Hi, I’m degu.<br><strong>Let’s make a little room.</strong>',
    scanning: 'Just looking!<br><strong>No files are changing.</strong>',
    preview: 'A little pause.<br><strong>Check the exact plan.</strong>',
    staging: 'Into the nook.<br><strong>Same HOME, same quota.</strong>',
    staged: 'Moved, but not freed.<br><strong>Want to try undo?</strong>',
    restoring: 'Back where it belongs.<br><strong>That’s what undo is for.</strong>',
    purging: 'Only what you confirmed.<br><strong>This step is permanent.</strong>',
    complete: 'Room to breathe.<br><strong>Your research stays.</strong>',
  };
  if (state.phase !== 'inspect') return lines[state.phase];
  return {
    pip: 'Packages can come back.<br><strong>Your work comes first.</strong>',
    models: 'These are big downloads.<br><strong>Worth a second look.</strong>',
    checkpoint: 'Your work, your story.<br><strong>This one stays.</strong>',
  }[state.focusId];
}
