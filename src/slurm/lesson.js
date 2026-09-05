import { t } from '../i18n/index.js';
import { button, escapeHtml, icon } from '../ui/helpers.js';
import { CLUSTER } from './model.js';
import { jobScript } from './commands.js';

const NOTICES = Object.freeze({
  login: 'The login desk is shared. Submit and inspect here; let Slurm place the heavy work on a compute node.',
  ticket: 'This envelope is your job. Drag it to the Slurm board, or select that board with your keyboard.',
  accounting: 'Do not resubmit just because the queue is empty. Check accounting and the output first; records can appear after a short delay on real sites.',
});

export function slurmLesson(state) {
  const views = { briefing, planning, submitted, pending, running, cancelled, accounting, complete };
  return `${views[state.phase](state)}${state.notice ? `<p class="notice" role="status">${t(NOTICES[state.notice])}</p>` : ''}`;
}

function heading(number, title) {
  return `<div class="lesson-eyebrow"><span class="lesson-number">${number}</span>${t(title)}</div>`;
}

function action(actionName, label, options = {}) {
  return button({ action: actionName, label: `${t(label)} ${options.arrow ? icon('arrow') : ''}`, ...options });
}

function briefing() {
  return `${heading('01', 'LET’S SEND AN EXPERIMENT')}<h2>${t('Big ideas start<br> with a little ticket.')}</h2>
    <p>${t('degu has an experiment to run. The cluster is a shared workshop, and Slurm arranges who can use its computers.')}</p>
    <div class="mission-card"><span class="mission-leaf">${icon('arrow')}</span><div><strong>${t('Where should this job go?')}</strong>
      <span>${t('Drag the little envelope to Slurm, or click a destination. The login desk is for submitting and checking jobs.')}</span></div></div>
    <div class="lesson-actions">${action('destination', 'Send it through Slurm', { id: 'scheduler', primary: true, arrow: true })}</div>
    <div class="lesson-footnote">${t('No cluster account needed')}</div>`;
}

function planning(state) {
  return `${heading('01', 'PACK WHAT YOU NEED')}<h2>${t('A small request.<br> A clear plan.')}</h2>
    <p>${t('This little partition has two compute nodes. Both are busy. Choose a node request and watch what happens.')}</p>
    <div class="node-choices">${nodeChoice(state, 1)}${nodeChoice(state, 3)}</div>
    <div class="resource-list"><div><span>${t('CPUs / task')}</span><strong>${CLUSTER.cpuPerTask}</strong></div>
      <div><span>${t('Memory / node')}</span><strong>${CLUSTER.memory}</strong></div><div><span>${t('Time limit')}</span><strong>${CLUSTER.walltime}</strong></div></div>
    <details class="path-details"><summary>${t('See the batch script')}</summary><pre>${escapeHtml(jobScript(state))}</pre></details>
    <p class="lesson-soft">${t('Slurm allocates these resources. It does not automatically turn a serial program into a parallel one.')}</p>
    <div class="lesson-actions">${action('submit', 'Submit my job', { primary: true, arrow: true })}</div>`;
}

function nodeChoice(state, count) {
  return `<button class="node-choice" data-action="nodes" data-id="${count}" data-focus-key="nodes-${count}"
    aria-pressed="${state.requestedNodes === count}"><strong>${t(count === 1 ? '1 node' : '3 nodes')}</strong>
    <span>${t(count === 1 ? 'A small experiment' : 'Try an oversized request')}</span></button>`;
}

function submitted(state) {
  return `${heading('02', 'A TICKET, NOT A START SIGNAL')}<h2>${t('Accepted.<br> Running? Let’s check.')}</h2>
    <div class="job-stamp"><span>JOB</span><strong>#${state.job.id}</strong><span>sbatch ✓</span></div>
    <p>${t('Slurm returned Job ID {id}. That means the request was accepted. It does not mean the program is running.', { id: state.job.id })}</p>
    <div class="lesson-revelation"><span class="revelation-icon">↔</span><div><strong>${t('Accepted ≠ running')}</strong>
      <p>${t('Follow this exact Job ID to find out what happens next.')}</p></div></div>
    <div class="lesson-actions">${action('queue', 'Look at the queue', { primary: true, arrow: true })}</div>`;
}

function pending(state) {
  const oversized = state.job.reason === 'PartitionNodeLimit';
  const explanation = oversized
    ? 'You asked for three nodes, but this teaching partition has only two. Waiting longer cannot create a third.'
    : 'The requested resources are in use. In this demo, advancing the clock lets one existing job finish normally.';
  return `${heading('03', 'A LITTLE PATIENCE, A LITTLE EVIDENCE')}<h2>${t('Waiting has<br> a reason.')}</h2>
    <span class="queue-state"><strong>PD</strong><code>${state.job.reason}</code></span>
    <p>${t(state.inspected ? explanation : 'PD means Pending. Look at the reason before changing your request or deciding to cancel.')}</p>
    ${state.inspected ? pendingActions(state, oversized) : `<div class="lesson-actions">${action('inspect', 'Read the job record', { primary: true, arrow: true })}</div>`}
    ${oversized && state.inspected ? `<p class="lesson-soft">${t('Real sites can reject oversized submissions or report different reasons. Always check their partition policy.')}</p>` : ''}`;
}

function pendingActions(state, oversized) {
  return `<div class="job-owner">${t('Job #{id} · owner: demo', { id: state.job.id })}</div>
    <div class="lesson-actions">${!oversized ? action('advance', 'Advance the demo clock', { primary: true, arrow: true }) : ''}
      ${action('cancel', 'Cancel my pending job', { kind: 'secondary', primary: oversized })}</div>
    <p class="lesson-soft">${t('Use the exact ID. The other users’ jobs stay untouched.')}</p>`;
}

function cancelled(state) {
  return `${heading('03', 'A CLEAN CHANGE OF PLAN')}<h2>${t('Your ticket<br> is withdrawn.')}</h2>
    <span class="queue-state"><strong>CANCELLED</strong><code>#${state.job.id}</code></span>
    <p>${t('Only your job #{id} was cancelled. Choose a smaller request and try submitting again.', { id: state.job.id })}</p>
    <div class="lesson-actions">${action('retry', 'Adjust the request', { primary: true, arrow: true })}</div>`;
}

function running() {
  return `${heading('04', 'A WORKSHOP OF YOUR OWN')}<h2>${t('Now we’re<br> running.')}</h2>
    <span class="queue-state running"><strong>R</strong><code>c1</code></span>
    <p>${t('R means Running. Slurm placed your job on c1. The other workshop is still working on someone else’s job.')}</p>
    <div class="lesson-actions">${action('finish', 'Finish this demo experiment', { id: 'success', primary: true, arrow: true })}
      ${action('finish', 'Try a program error instead', { id: 'failure', kind: 'secondary' })}</div>
    <p class="lesson-soft">${t('The demo clock is yours to control. This does not predict real queue times or execution speed.')}</p>`;
}

function accounting() {
  return `${heading('05', 'GONE FROM THE QUEUE, NOT THE RECORD')}<h2>${t('An empty queue.<br> What happened?')}</h2>
    <p>${t('Your Job ID is no longer in squeue. That alone does not tell you whether the program succeeded.')}</p>
    <div class="lesson-actions">${action('result', 'Check the result with sacct', { primary: true, arrow: true })}
      ${action('resubmit', 'Should I submit again?', { kind: 'secondary' })}</div>`;
}

function complete(state) {
  const succeeded = state.job.state === 'COMPLETED';
  return `${heading('05', 'A RESULT YOU CAN READ')}<h2>${t('A little job,<br> understood.')}</h2>
    <span class="queue-state ${succeeded ? 'running' : 'failed'}"><strong>${state.job.state}</strong><code>${state.job.exitCode}</code></span>
    <p>${t(succeeded ? 'The program finished successfully. ExitCode 0:0 means exit status 0 and no terminating signal.'
      : 'This demo deliberately returned exit status 42. FAILED with 42:0 points to the program result, not a broken scheduler.')}</p>
    ${!succeeded ? `<div class="lesson-revelation"><strong>${t('Allocated ≠ succeeded')}</strong></div>` : ''}
    <p class="lesson-soft">${t('Back at HOME, an older checkpoint and useful caches share your quota. Keep the work that matters and make room for the next experiment.')}</p>
    <div class="lesson-actions">${action('continueCleanup', 'Back HOME: make some room', { primary: true, arrow: true })}
      ${action('retry', 'Try another experiment', { kind: 'secondary' })}</div>`;
}
