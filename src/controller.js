import { initialState, transition } from './model.js';

const SCAN_HOP_MS = 650;
const STAGE_APPROACH_MS = 500;
const STAGE_CARRY_MS = 900;
const RESTORE_MS = 1100;
const PURGE_HOP_MS = 900;

export function createController(options) {
  const { scenario, clock, render } = options;
  let state = initialState();
  const send = (event) => {
    state = transition(state, { ...event, at: clock.now() }, scenario);
    render(state);
  };
  const wait = (duration) => clock.wait(clock.reducedMotion() ? 0 : duration);
  const actions = createActions({ scenario, send, wait, current: () => state });
  return Object.freeze({
    current: () => state,
    refresh: () => render(state),
    reset: () => { state = initialState(); render(state); },
    dispatch: async (action, payload = {}) => {
      if (Object.hasOwn(actions, action)) return actions[action](payload);
      send({ ...payload, type: action });
    },
  });
}

function createActions(context) {
  return Object.freeze({
    scan: async () => {
      context.send({ type: 'scanStart' });
      for (const item of context.scenario.locations) {
        await context.wait(SCAN_HOP_MS);
        context.send({ type: 'scanVisit', id: item.id });
      }
      await context.wait(SCAN_HOP_MS);
      context.send({ type: 'scanFinish' });
    },
    stage: () => stage(context),
    undo: async () => {
      context.send({ type: 'undoStart' });
      await context.wait(RESTORE_MS);
      context.send({ type: 'undoFinish' });
    },
    purge: (payload) => purge(context, payload),
  });
}

async function stage(context) {
  const ids = [...context.current().planIds];
  context.send({ type: 'stageStart' });
  for (const id of ids) {
    context.send({ type: 'busyItem', id });
    await context.wait(STAGE_APPROACH_MS);
    context.send({ type: 'carryItem', id });
    await context.wait(STAGE_CARRY_MS);
    context.send({ type: 'stageItem', id });
  }
  context.send({ type: 'stageFinish' });
}

async function purge(context, payload) {
  const ids = [...context.current().trashIds];
  context.send({ type: 'purgeStart', confirmation: payload.confirmation });
  for (const id of ids) {
    context.send({ type: 'busyItem', id });
    await context.wait(PURGE_HOP_MS);
    context.send({ type: 'purgeItem', id });
  }
  context.send({ type: 'purgeFinish' });
}
