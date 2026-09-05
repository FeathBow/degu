import { locationById } from './scenario.js';

export function cleanCommand(scenario, ids, preview = false) {
  const locations = ids.map((id) => locationById(scenario, id));
  const args = ['degu', 'clean'];
  const previewArgs = preview ? ['--dry-run'] : [];
  const reviewArgs = locations.some((item) => item.disposition === 'opt_in')
    ? ['--include-review'] : [];
  const paths = locations.flatMap((item) => ['--path', `"${item.path}"`]);
  return [...args, ...previewArgs, ...reviewArgs, ...paths].join(' ');
}

export function currentCommand(scenario, state) {
  if (state.phase === 'welcome' || state.phase === 'scanning') return 'degu scan';
  if (state.phase === 'restoring') return 'degu undo';
  if (state.phase === 'purging' || state.phase === 'complete') return 'degu trash purge';
  if (state.phase === 'staged') return 'degu trash list';
  if (state.phase === 'staging') return cleanCommand(scenario, state.planIds);
  if (state.selectedIds.length) return cleanCommand(scenario, state.selectedIds, true);
  return 'degu scan --details';
}
