import { cleanCommand } from './commands.js';
import { locationById, totalSize } from './scenario.js';

const RECORD_DIGITS = 3;

export function initialState() {
  return Object.freeze({
    phase: 'welcome', focusId: 'pip', selectedIds: [], reviewedIds: [],
    planIds: [], trashIds: [], purgedIds: [], visitedIds: [],
    activity: [], busyId: null, carryingId: null, notice: null, dialog: null,
  });
}

function requirePhase(state, allowed) {
  if (!allowed.includes(state.phase)) {
    throw new Error(`Tutorial action is not available during ${state.phase}.`);
  }
}

function requireCondition(condition, message) {
  if (!condition) throw new Error(message);
}

function addRecord(state, request) {
  const { scenario, ids, action, command, at } = request;
  const record = Object.freeze({
    id: `DEMO-${String(state.activity.length + 1).padStart(RECORD_DIGITS, '0')}`,
    simulated: true, at, action, command,
    paths: ids.map((id) => locationById(scenario, id).path),
    sizeMiB: totalSize(scenario, ids),
  });
  return [...state.activity, record];
}

function scanStart(state) {
  requirePhase(state, ['welcome']);
  return { ...state, phase: 'scanning', notice: null };
}

function scanVisit(state, event) {
  requirePhase(state, ['scanning']);
  locationById(event.scenario, event.id);
  return { ...state, focusId: event.id, visitedIds: [...state.visitedIds, event.id] };
}

function scanFinish(state) {
  requirePhase(state, ['scanning']);
  return { ...state, phase: 'inspect', focusId: 'pip', notice: 'Scan complete. Nothing has changed.' };
}

function inspect(state, event) {
  requirePhase(state, ['inspect']);
  locationById(event.scenario, event.id);
  return { ...state, focusId: event.id, notice: null };
}

function select(state, event) {
  requirePhase(state, ['inspect']);
  const item = locationById(event.scenario, event.id);
  requireCondition(item.disposition !== 'report_only', 'A checkpoint cannot enter a cleanup plan.');
  requireCondition(item.disposition === 'eligible' || state.reviewedIds.includes(item.id),
    'Review the model download cost before including this exact path.');
  const selectedIds = state.selectedIds.includes(item.id)
    ? state.selectedIds.filter((id) => id !== item.id) : [...state.selectedIds, item.id];
  return { ...state, selectedIds, notice: null };
}

function review(state, event) {
  requirePhase(state, ['inspect']);
  const item = locationById(event.scenario, event.id);
  requireCondition(item.disposition === 'opt_in', 'This location does not need a review opt-in.');
  return { ...state, reviewedIds: [...new Set([...state.reviewedIds, item.id])],
    selectedIds: [...new Set([...state.selectedIds, item.id])], notice: 'Only this exact model cache was included.' };
}

function preview(state, event) {
  requirePhase(state, ['inspect']);
  requireCondition(state.selectedIds.length > 0, 'Select at least one cache to preview.');
  const planIds = [...state.selectedIds];
  return { ...state, phase: 'preview', planIds, notice: null,
    activity: addRecord(state, { ...event, ids: planIds, action: 'Previewed',
      command: cleanCommand(event.scenario, planIds, true) }) };
}

function back(state) {
  requirePhase(state, ['preview']);
  return { ...state, phase: 'inspect', planIds: [] };
}

function stageStart(state) {
  requirePhase(state, ['preview']);
  return { ...state, phase: 'staging', busyId: state.planIds[0] };
}

function stageItem(state, event) {
  requirePhase(state, ['staging']);
  requireCondition(state.planIds.includes(event.id), 'Staging cannot broaden the reviewed plan.');
  requireCondition(!state.trashIds.includes(event.id), 'This cache has already been staged.');
  return { ...state, trashIds: [...state.trashIds, event.id], carryingId: null };
}

function carryItem(state, event) {
  requirePhase(state, ['staging']);
  requireCondition(event.id === state.busyId && state.planIds.includes(event.id), 'Only the current planned cache can be carried.');
  return { ...state, carryingId: event.id };
}

function busyItem(state, event) {
  requirePhase(state, ['staging', 'purging']);
  requireCondition(state.planIds.includes(event.id), 'This path is outside the reviewed plan.');
  return { ...state, busyId: event.id, focusId: event.id };
}

function stageFinish(state, event) {
  requirePhase(state, ['staging']);
  requireCondition(state.planIds.every((id) => state.trashIds.includes(id)), 'Staging is incomplete.');
  return { ...state, phase: 'staged', busyId: null,
    activity: addRecord(state, { ...event, ids: state.planIds, action: 'Staged',
      command: cleanCommand(event.scenario, state.planIds) }) };
}

function undoStart(state) {
  requirePhase(state, ['staged']);
  return { ...state, phase: 'restoring', dialog: null };
}

function undoFinish(state, event) {
  requirePhase(state, ['restoring']);
  return { ...state, phase: 'inspect', trashIds: [], selectedIds: [], planIds: [],
    focusId: 'pip', notice: 'Restored to the original paths. Quota usage never changed.',
    activity: addRecord(state, { ...event, ids: state.trashIds, action: 'Restored', command: 'degu undo' }) };
}

function requestPurge(state) {
  requirePhase(state, ['staged']);
  return { ...state, dialog: 'purge' };
}

function purgeStart(state, event) {
  requirePhase(state, ['staged']);
  requireCondition(state.dialog === 'purge' && event.confirmation === 'purge',
    'Type purge to confirm the simulated permanent deletion.');
  return { ...state, phase: 'purging', dialog: null, busyId: state.trashIds[0] };
}

function purgeItem(state, event) {
  requirePhase(state, ['purging']);
  requireCondition(state.trashIds.includes(event.id), 'Only the reviewed trash can be purged.');
  return { ...state, trashIds: state.trashIds.filter((id) => id !== event.id),
    purgedIds: [...state.purgedIds, event.id] };
}

function purgeFinish(state, event) {
  requirePhase(state, ['purging']);
  requireCondition(state.trashIds.length === 0, 'The purge has not completed.');
  return { ...state, phase: 'complete', busyId: null,
    activity: addRecord(state, { ...event, ids: state.planIds, action: 'Purged', command: 'degu trash purge' }) };
}

function openReceipt(state) {
  requirePhase(state, ['welcome', 'inspect', 'preview', 'staged', 'complete']);
  return { ...state, dialog: 'receipt' };
}

const TRANSITIONS = Object.freeze({
  scanStart, scanVisit, scanFinish, inspect, select, review, preview, back,
  stageStart, busyItem, carryItem, stageItem, stageFinish, undoStart, undoFinish,
  requestPurge, purgeStart, purgeItem, purgeFinish, openReceipt,
  closeDialog: (state) => ({ ...state, dialog: null }),
});

export function transition(state, event, scenario) {
  if (!Object.hasOwn(TRANSITIONS, event.type)) throw new Error(`Unknown tutorial action: ${event.type}`);
  const handler = TRANSITIONS[event.type];
  return Object.freeze(handler(state, { ...event, scenario }));
}

export function receiptFor(state, scenario) {
  return Object.freeze({
    schema_version: 1, simulated: true, scenario: scenario.id,
    notice: 'Browser tutorial data. No real files were inspected or modified.',
    capacityMiB: scenario.capacityMiB, initialUsedMiB: scenario.initialUsedMiB,
    removedMiB: totalSize(scenario, state.purgedIds),
    checkpointPreserved: !state.purgedIds.includes('checkpoint'),
    activity: state.activity,
  });
}
