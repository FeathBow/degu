import { t } from '../i18n/index.js';
import { art, icon } from '../ui/helpers.js';
import { navigation, toolbar, footer } from '../ui/layouts.js';
import { chapterNav } from '../ui/chapters.js';
import { terminalFrame } from '../ui/components.js';
import { syncPreferences } from '../preferences.js';
import { slurmCommand, slurmOutput } from './commands.js';
import { slurmLesson } from './lesson.js';
import { clusterShell, renderCluster } from './scene.js';

const STEPS = Object.freeze({ briefing: 0, planning: 0, submitted: 1, pending: 2, cancelled: 2, running: 3, accounting: 4, complete: 4 });

export function createSlurmView(options) {
  const { root, announce } = options;
  let activeLanguage = null;
  let previousPhase = null;
  return (state) => {
    const focusKey = document.activeElement?.dataset.focusKey;
    const inLesson = Boolean(document.activeElement?.closest('#lesson'));
    if (activeLanguage !== document.documentElement.lang || root.dataset.activeChapter !== 'slurm') {
      root.innerHTML = shell();
      root.dataset.activeChapter = 'slurm';
      activeLanguage = document.documentElement.lang;
    }
    root.querySelector('#slurm-tutorial').dataset.phase = state.phase;
    root.querySelector('#lesson').innerHTML = slurmLesson(state);
    root.querySelector('#slurm-progress').innerHTML = progress(state);
    root.querySelector('#terminal-slot').innerHTML = terminalFrame({ command: slurmCommand(state), output: slurmOutput(state), caption: t('This is a teaching scenario. No scheduler or shell command is running.') });
    renderCluster(root, state);
    syncPreferences();
    restoreFocus(root, { focusKey, inLesson, changed: Boolean(previousPhase && previousPhase !== state.phase) });
    if (previousPhase !== state.phase) {
      announce.textContent = root.querySelector('#lesson').textContent;
      if (previousPhase && matchMedia('(max-width: 820px)').matches) root.querySelector('#lesson').scrollIntoView({ behavior: 'instant' });
    }
    previousPhase = state.phase;
  };
}

function shell() {
  return `<div class="page layout-habitat slurm-page">${navigation()}<section class="hero"><div>
    <div class="eyebrow">${art('leaf')} ${t('A SMALL HPC ADVENTURE')}</div><h1>${t('Small jobs. <em>Big possibilities.</em>')}</h1></div>
    <p class="hero-description">${t('A shared workshop. A curious degu.<br> Learn how a little job becomes <strong>a real result.</strong>')}</p></section>
    ${chapterNav('slurm')}<main id="slurm-tutorial">${toolbar()}<div class="cluster-grid">
      <section id="lesson" class="lesson-panel" tabindex="-1" aria-label="${t('Your tutorial step')}"></section>
      <div class="cluster-world"><div class="cluster-summary"><span>${icon('home')} ${t('Compute workshops')}</span><strong>${t('2 nodes · shared fairly')}</strong></div>
        ${clusterShell()}<div id="slurm-progress" class="journey"></div></div></div>
      <section id="terminal-slot" class="terminal" aria-label="${t('Corresponding Slurm command')}"></section></main>
    ${footer({ detail: 'Browser lesson · No cluster connection needed.' })}<p class="slurm-reference"><a href="https://slurm.schedmd.com/quickstart.html">${t('Slurm’s official quick start')} ↗</a></p></div>`;
}

function progress(state) {
  const active = STEPS[state.phase];
  return `<ol class="journey-list" aria-label="${t('Tutorial progress')}">${['Resources', 'Submit', 'Queue', 'Run', 'Check'].map((label, index) =>
    `<li class="${index === active ? 'current' : ''} ${index < active ? 'passed' : ''}" ${index === active ? 'aria-current="step"' : ''}>
      <span class="journey-dot">${index < active ? '✓' : index + 1}</span><span>${t(label)}</span></li>`).join('')}</ol>`;
}

function restoreFocus(root, context) {
  const target = context.focusKey ? root.querySelector(`[data-focus-key="${CSS.escape(context.focusKey)}"]`) : null;
  if (target && !target.disabled && !target.hidden) return target.focus({ preventScroll: true });
  if (context.inLesson || context.changed) root.querySelector('#lesson [data-primary]')?.focus({ preventScroll: true });
}
