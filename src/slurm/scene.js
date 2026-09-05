import { t } from '../i18n/index.js';
import { art, icon } from '../ui/helpers.js';

const POSITIONS = Object.freeze({ briefing: [21, 78], planning: [48, 75], submitted: [28, 77], pending: [28, 77],
  running: [66, 54], cancelled: [29, 76], accounting: [31, 74], complete: [25, 74] });

export function clusterArt(name, className = '') {
  return `<svg class="${className}" aria-hidden="true"><use href="./assets/cluster.svg#${name}"></use></svg>`;
}

export function clusterShell() {
  return `<section class="scene-card cluster-card" aria-label="${t('A shared cluster, in miniature')}">
    <div class="scene-topline"><span class="scene-title">${icon('home')} ${t('A tiny cluster')}</span>
      <span class="scene-mode">${t('TWO LITTLE WORKSHOPS · DEMO')}</span></div>
    <div class="cluster-map"><div class="cluster-hill" aria-hidden="true"></div><div class="cluster-hill second" aria-hidden="true"></div>
      <svg class="cluster-path" viewBox="0 0 700 390" preserveAspectRatio="none" aria-hidden="true">
        <path d="M130 290 Q290 335 350 235 T555 170 M350 235 Q500 350 575 320"/></svg>
      <button class="delivery-target login-desk" data-drop-target data-action="destination" data-id="login" data-focus-key="destination-login">
        ${clusterArt('desk')}<strong>${t('Login desk')}</strong><span>${t('Submit & inspect')}</span></button>
      <button class="delivery-target dispatch-board" data-drop-target data-action="destination" data-id="scheduler" data-focus-key="destination-scheduler">
        ${clusterArt('scheduler')}<strong>${t('Slurm dispatch')}</strong><span>${t('Queue & allocate')}</span></button>
      <div class="workshop workshop-one">${clusterArt('workshop')}<strong>c1</strong><span class="workshop-state" data-workshop-one></span></div>
      <div class="workshop workshop-two">${clusterArt('workshop')}<strong>c2</strong><span class="workshop-state">${t('Another user’s job')}</span></div>
      <button class="job-envelope" data-job-ticket draggable="true" data-action="hint" data-focus-key="job-ticket" aria-label="${t('Your job ticket')}">
        ${clusterArt('ticket')}<span>${t('Drag to Slurm')}</span></button>
      <div class="cluster-degu" data-cluster-degu>${art('degu', 'mascot-art')}<span class="cluster-carry">${clusterArt('ticket')}</span></div>
      <div class="board-ticket" data-board-ticket hidden><span>JOB</span><strong data-board-id></strong><span data-board-status></span></div>
    </div><div class="scene-bottomline"><p>${t('A job ticket goes to Slurm. A compute node does the work.')}</p></div></section>`;
}

export function renderCluster(root, state) {
  const position = POSITIONS[state.phase];
  const degu = root.querySelector('[data-cluster-degu]');
  degu.style.setProperty('--degu-x', `${position[0]}%`);
  degu.style.setProperty('--degu-y', `${position[1]}%`);
  degu.classList.toggle('has-ticket', ['planning', 'running'].includes(state.phase));
  degu.classList.toggle('is-happy', state.phase === 'complete' && state.job.state === 'COMPLETED');
  root.querySelector('[data-job-ticket]').hidden = state.phase !== 'briefing';
  for (const target of root.querySelectorAll('[data-drop-target]')) target.disabled = state.phase !== 'briefing';
  const active = state.phase === 'running';
  const finished = ['accounting', 'complete'].includes(state.phase);
  root.querySelector('.workshop-one').classList.toggle('is-running', active);
  root.querySelector('[data-workshop-one]').textContent = t(active ? 'Your job is running' : finished ? 'Ready for another job' : 'Another user’s job');
  const ticket = root.querySelector('[data-board-ticket]');
  ticket.hidden = !['submitted', 'pending', 'cancelled'].includes(state.phase);
  if (!ticket.hidden) {
    root.querySelector('[data-board-id]').textContent = `#${state.job.id}`;
    root.querySelector('[data-board-status]').textContent = state.phase === 'cancelled' ? 'CANCELLED' : 'PD';
  }
}

export function bindTicketDrag(options) {
  const { root, dispatch } = options;
  const type = 'application/x-degu-ticket';
  root.addEventListener('dragstart', (event) => {
    if (!event.target.closest('[data-job-ticket]')) return;
    event.dataTransfer.setData(type, 'job');
    event.dataTransfer.effectAllowed = 'move';
  });
  root.addEventListener('dragover', (event) => {
    const target = event.target.closest('[data-drop-target]');
    if (!target || target.disabled || !event.dataTransfer.types.includes(type)) return;
    event.preventDefault();
    target.classList.add('is-drop-target');
  });
  root.addEventListener('dragleave', (event) => event.target.closest('[data-drop-target]')?.classList.remove('is-drop-target'));
  root.addEventListener('drop', (event) => {
    const target = event.target.closest('[data-drop-target]');
    if (!target || target.disabled || event.dataTransfer.getData(type) !== 'job') return;
    event.preventDefault();
    target.classList.remove('is-drop-target');
    dispatch('destination', { id: target.dataset.id });
  });
  root.addEventListener('dragend', () => root.querySelectorAll('.is-drop-target').forEach((target) => target.classList.remove('is-drop-target')));
}
