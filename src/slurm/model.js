export const CLUSTER = Object.freeze({ nodeCount: 2, cpuPerTask: 2, memory: '512M', walltime: '00:02:00', firstJobId: 42 });
const NODE_CHOICES = Object.freeze([1, 3]);

export function initialSlurmState() {
  return Object.freeze({ phase: 'briefing', requestedNodes: 1, nextJobId: CLUSTER.firstJobId,
    job: null, inspected: false, notice: null, history: Object.freeze([]) });
}

function requirePhase(state, phases) {
  if (!phases.includes(state.phase)) throw new Error(`Slurm lesson action is unavailable during ${state.phase}.`);
}

function change(state, phase, updates = {}) {
  return Object.freeze({ ...state, notice: null, ...updates, phase });
}

function destination(state, event) {
  requirePhase(state, ['briefing']);
  if (event.id === 'login') return change(state, 'briefing', { notice: 'login' });
  if (event.id !== 'scheduler') throw new Error('Unknown experiment destination.');
  return change(state, 'planning');
}

function nodes(state, event) {
  requirePhase(state, ['planning']);
  const requestedNodes = Number(event.id);
  if (!NODE_CHOICES.includes(requestedNodes)) throw new Error('Unknown resource choice.');
  return change(state, 'planning', { requestedNodes });
}

function submit(state) {
  requirePhase(state, ['planning']);
  const job = Object.freeze({ id: state.nextJobId, owner: 'demo', state: 'PENDING',
    reason: state.requestedNodes > CLUSTER.nodeCount ? 'PartitionNodeLimit' : 'Resources', exitCode: null });
  return change(state, 'submitted', { job, nextJobId: state.nextJobId + 1, inspected: false });
}

function queue(state) {
  requirePhase(state, ['submitted']);
  return change(state, 'pending');
}

function inspect(state) {
  requirePhase(state, ['pending']);
  return change(state, 'pending', { inspected: true });
}

function advance(state) {
  requirePhase(state, ['pending']);
  if (!state.inspected || state.job.reason !== 'Resources') throw new Error('Review the pending reason before advancing the demo clock.');
  return change(state, 'running', { job: Object.freeze({ ...state.job, state: 'RUNNING', reason: null }) });
}

function cancel(state) {
  requirePhase(state, ['pending']);
  if (!state.inspected) throw new Error('Check the job ID and pending reason before cancelling.');
  const job = Object.freeze({ ...state.job, state: 'CANCELLED', exitCode: '0:0' });
  return change(state, 'cancelled', { job, history: Object.freeze([...state.history, job]) });
}

function retry(state) {
  requirePhase(state, ['cancelled', 'complete']);
  return change(state, 'planning', { job: null, inspected: false });
}

function finish(state, event) {
  requirePhase(state, ['running']);
  if (!['success', 'failure'].includes(event.id)) throw new Error('Choose an explicit demo program outcome.');
  const succeeded = event.id === 'success';
  const job = Object.freeze({ ...state.job, state: succeeded ? 'COMPLETED' : 'FAILED', exitCode: succeeded ? '0:0' : '42:0' });
  return change(state, 'accounting', { job });
}

function result(state) {
  requirePhase(state, ['accounting']);
  return change(state, 'complete', { history: Object.freeze([...state.history, state.job]) });
}

function hint(state) {
  requirePhase(state, ['briefing']);
  return change(state, state.phase, { notice: 'ticket' });
}

function resubmit(state) {
  requirePhase(state, ['accounting']);
  return change(state, state.phase, { notice: 'accounting' });
}

const ACTIONS = Object.freeze({ destination, nodes, submit, queue, inspect, advance, cancel, retry, finish, result, hint, resubmit });

export function slurmTransition(state, event) {
  if (!Object.hasOwn(ACTIONS, event.type)) throw new Error(`Unknown Slurm lesson action: ${event.type}`);
  return ACTIONS[event.type](state, event);
}

export function createSlurmController(options) {
  let state = initialSlurmState();
  return Object.freeze({
    current: () => state,
    refresh: () => options.render(state),
    reset: () => { state = initialSlurmState(); options.render(state); },
    dispatch: (type, payload = {}) => { state = slurmTransition(state, { ...payload, type }); options.render(state); },
  });
}
