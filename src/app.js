import { SCENARIO } from './scenario.js';
import { createController } from './controller.js';
import { receiptFor } from './model.js';
import { browserClock, copyCommand, downloadReceipt, reportError } from './browser.js';
import { createSlurmController } from './slurm/model.js';
import { createSlurmView } from './slurm/view.js';
import { createView } from './ui/view.js';
import { createDialogs } from './ui/dialogs.js';
import { chapterFromUrl, updateChapterNav } from './ui/chapters.js';
import { isBusy } from './ui/helpers.js';

export function createApp(options) {
  const { root, announce } = options;
  const route = createRoute(new URL(location.href));
  const views = Object.freeze({ cleanup: createView({ root, scenario: SCENARIO, announce }), slurm: createSlurmView({ root, announce }) });
  const controllers = Object.freeze({
    cleanup: createController({ scenario: SCENARIO, clock: browserClock, render: () => refresh() }),
    slurm: createSlurmController({ render: () => refresh() }),
  });
  const dialogs = createDialogs({ root: document.querySelector('#overlay-root'), scenario: SCENARIO,
    dispatch: (action) => act(action) });
  const context = Object.freeze({ root, route, views, controllers, dialogs });
  const refresh = () => renderCurrent(context);
  const act = async (action, payload = {}) => {
    try { await perform(context, { action, payload }); }
    catch (error) { reportError(error); }
  };
  return Object.freeze({ act, refresh });
}

function createRoute(url) {
  let current = chapterFromUrl(url);
  return Object.freeze({
    current: () => current,
    update: (chapter) => {
      const next = new URL(location.href);
      next.searchParams.set('chapter', chapter);
      current = chapterFromUrl(next);
      history.replaceState(null, '', next);
    },
  });
}

function renderCurrent(context) {
  const chapter = context.route.current();
  const state = context.controllers[chapter].current();
  const cleanup = context.controllers.cleanup.current();
  const slurm = context.controllers.slurm.current();
  context.views[chapter](state);
  context.dialogs(cleanup);
  updateChapterNav({ busy: isBusy(cleanup), completed: {
    cleanup: cleanup.phase === 'complete', slurm: slurm.history.some((job) => ['COMPLETED', 'FAILED'].includes(job.state)),
  } });
}

async function perform(context, event) {
  const { action, payload } = event;
  const controller = context.controllers[context.route.current()];
  if (action === 'reset') return controller.reset();
  if (action === 'copy') return copyCommand(context.root);
  if (action === 'download') return downloadReceipt(receiptFor(context.controllers.cleanup.current(), SCENARIO));
  if (action === 'chapter' || action === 'continueCleanup') {
    context.route.update(action === 'continueCleanup' ? 'cleanup' : payload.id);
    return renderCurrent(context);
  }
  await controller.dispatch(action, payload);
  if (action === 'inspect' && matchMedia('(max-width: 820px)').matches) {
    context.root.querySelector('#lesson').scrollIntoView({ behavior: browserClock.reducedMotion() ? 'instant' : 'smooth', block: 'start' });
  }
}
