import { renderQuota, journey, terminal, activityLink } from './components.js';
import { inspector } from './inspector.js';
import { isBusy, stepLabel } from './helpers.js';
import { layoutShell } from './layouts.js';
import { renderScene } from './scene.js';
import { syncPreferences } from '../preferences.js';
import { t } from '../i18n/index.js';

export function createView(options) {
  const { root, scenario, announce } = options;
  let activeLanguage = null;
  let previousState = null;
  return (state) => {
    const focusKey = document.activeElement?.dataset.focusKey;
    const hadLessonFocus = Boolean(document.activeElement?.closest('#lesson'));
    if (activeLanguage !== document.documentElement.lang || root.dataset.activeChapter !== 'cleanup') {
      root.innerHTML = layoutShell(scenario);
      root.dataset.activeChapter = 'cleanup';
      activeLanguage = document.documentElement.lang;
    }
    updateSlots(root, scenario, state);
    syncPreferences();
    const phaseChanged = previousState && previousState.phase !== state.phase;
    restoreFocus(root, { focusKey, hadLessonFocus, phaseChanged, state });
    if (phaseChanged && !isBusy(state) && state.phase !== 'welcome' && matchMedia('(max-width: 820px)').matches) {
      root.querySelector('#lesson').scrollIntoView({ behavior: 'instant', block: 'start' });
    }
    if (phaseChanged || previousState?.focusId !== state.focusId) {
      announce.textContent = `${stepLabel(state.phase)}. ${root.querySelector('#lesson h2').textContent} ${state.notice ? t(state.notice) : ''}`;
    }
    previousState = state;
  };
}

function updateSlots(root, scenario, state) {
  root.querySelector('#tutorial').dataset.phase = state.phase;
  renderQuota(root.querySelector('#quota-slot'), scenario, state);
  root.querySelector('#journey-slot').innerHTML = journey(state);
  root.querySelector('#lesson').innerHTML = inspector(scenario, state);
  root.querySelector('#terminal-slot').innerHTML = terminal(scenario, state);
  root.querySelector('#activity-slot').innerHTML = activityLink(state);
  root.querySelector('.restart-button').disabled = isBusy(state);
  renderScene(root, scenario, state);
}

function restoreFocus(root, context) {
  if (context.state.dialog) return;
  const target = context.focusKey
    ? root.querySelector(`[data-focus-key="${CSS.escape(context.focusKey)}"]`) : null;
  if (target && !target.disabled) return target.focus({ preventScroll: true });
  if (context.hadLessonFocus || context.phaseChanged) {
    const next = root.querySelector('#lesson [data-primary]:not(:disabled)') || root.querySelector('#lesson');
    next.focus({ preventScroll: true });
  }
}
