const MIB_PER_GIB = 1024;

export const SCENARIO = Object.freeze({
  id: 'initialized-ext4-home',
  home: '/home/demo',
  filesystem: 'ext4',
  capacityMiB: 10 * MIB_PER_GIB,
  initialUsedMiB: 9.5 * MIB_PER_GIB,
  goalMiB: 2 * MIB_PER_GIB,
  locations: Object.freeze([
    Object.freeze({
      id: 'pip', name: 'Package cache', source: 'pip',
      path: '/home/demo/.cache/pip', sizeMiB: 2 * MIB_PER_GIB,
      disposition: 'eligible', label: 'Ready to preview',
      why: 'Downloaded packages that pip can fetch again. This sample cache has passed the location and ownership checks.',
      consequence: 'Packages may need to be downloaded again when you install them.',
      hint: 'A good place to start. This cache is enough to complete your mission.',
      symbol: 'packages', position: Object.freeze({ x: 23, y: 48 }),
    }),
    Object.freeze({
      id: 'models', name: 'Model cache', source: 'Hugging Face',
      path: '/home/demo/.cache/huggingface/hub/models--demo--model',
      sizeMiB: 5 * MIB_PER_GIB, disposition: 'opt_in', label: 'Needs review',
      why: 'These model files can be downloaded again, but doing so costs bandwidth and time. A large cache is not automatically the best choice.',
      consequence: 'The model must be downloaded again before its next use. Offline access may be affected.',
      hint: 'You can include this exact cache after reviewing its cost, or keep it for your next experiment.',
      symbol: 'models', position: Object.freeze({ x: 72, y: 38 }),
    }),
    Object.freeze({
      id: 'checkpoint', name: 'Your checkpoint', source: 'Experiment 42',
      path: '/home/demo/experiments/run-42/checkpoints',
      sizeMiB: 2 * MIB_PER_GIB, disposition: 'report_only', label: 'Not managed',
      why: 'This checkpoint contains your experiment results. degu reports its size but cannot put it in a cleanup plan.',
      consequence: 'It stays exactly where it is. It is never selected, staged, or purged in this tutorial.',
      hint: 'Some things are worth keeping. Your research is one of them.',
      symbol: 'checkpoint', position: Object.freeze({ x: 75, y: 76 }),
    }),
  ]),
});

export function formatSize(sizeMiB) {
  const gib = sizeMiB / MIB_PER_GIB;
  return `${Number.isInteger(gib) ? gib : gib.toFixed(1)} GiB`;
}

export function locationById(scenario, id) {
  const location = scenario.locations.find((item) => item.id === id);
  if (!location) throw new Error(`Unknown tutorial location: ${id}`);
  return location;
}

export function totalSize(scenario, ids) {
  return ids.reduce((sum, id) => sum + locationById(scenario, id).sizeMiB, 0);
}

export function quotaFor(scenario, state) {
  const removedMiB = totalSize(scenario, state.purgedIds);
  const usedMiB = scenario.initialUsedMiB - removedMiB;
  return Object.freeze({ removedMiB, usedMiB, freeMiB: scenario.capacityMiB - usedMiB });
}
