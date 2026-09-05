import { createApp } from './app.js';
import { reportError } from './browser.js';
import { bindPreferences } from './preferences.js';
import { bindTicketDrag } from './slurm/scene.js';

function mount() {
  if (document.documentElement.dataset.preferenceError) throw new Error(document.documentElement.dataset.preferenceError);
  const root = document.querySelector('#app');
  const app = createApp({ root, announce: document.querySelector('#announcement') });
  bindActions(app);
  bindTicketDrag({ root, dispatch: app.act });
  bindPreferences({ refresh: app.refresh, onError: reportError });
  app.refresh();
}

function bindActions(context) {
  document.addEventListener('click', (event) => {
    const target = event.target.closest('[data-action]');
    if (target && !target.disabled) context.act(target.dataset.action, { id: target.dataset.id });
    const chapter = event.target.closest('[data-chapter]');
    if (chapter && !chapter.disabled) context.act('chapter', { id: chapter.dataset.chapter });
  });
  document.addEventListener('input', (event) => {
    if (event.target.id !== 'purge-confirmation') return;
    document.querySelector('#purge-submit').disabled = event.target.value !== 'purge';
  });
  document.addEventListener('submit', (event) => {
    if (event.target.id !== 'purge-form') return;
    event.preventDefault();
    context.act('purge', { confirmation: new FormData(event.target).get('confirmation') });
  });
}

try { mount(); } catch (error) { reportError(error); }
