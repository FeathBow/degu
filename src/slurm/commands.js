import { CLUSTER } from './model.js';

export function jobScript(state) {
  return `#!/bin/bash
#SBATCH --job-name=degu-first-job
#SBATCH --nodes=${state.requestedNodes}
#SBATCH --ntasks=${state.requestedNodes}
#SBATCH --cpus-per-task=${CLUSTER.cpuPerTask}
#SBATCH --mem=${CLUSTER.memory}
#SBATCH --time=${CLUSTER.walltime}
#SBATCH --output=degu-%j.out

set -eu
srun hostname`;
}

export function slurmCommand(state) {
  const id = state.job?.id;
  const commands = {
    briefing: 'sinfo', planning: 'cat first-job.sh', submitted: 'sbatch --parsable first-job.sh',
    pending: state.inspected ? `scontrol show job ${id}` : `squeue -j ${id}`,
    running: `squeue -j ${id}`, cancelled: `scancel ${id}`,
    accounting: `squeue -j ${id}`, complete: `sacct -X -j ${id} --format=JobID,State,ExitCode,NodeList`,
  };
  return commands[state.phase];
}

export function slurmOutput(state) {
  if (state.phase === 'briefing') return 'PARTITION  NODES  STATE  NODELIST\ncpu*           2  alloc  c[1-2]';
  if (state.phase === 'planning') return jobScript(state);
  if (state.phase === 'submitted') return String(state.job.id);
  if (state.phase === 'pending' && state.inspected) return jobRecord(state);
  if (state.phase === 'cancelled') return '';
  if (state.phase === 'complete') return `JobID  State       ExitCode  NodeList\n${state.job.id}     ${state.job.state.padEnd(11)} ${state.job.exitCode.padEnd(9)} c1`;
  const header = 'JOBID  PARTITION  NAME            ST  NODELIST(REASON)';
  if (state.phase === 'accounting') return header;
  const status = state.phase === 'running' ? 'R   c1' : `PD  (${state.job.reason})`;
  return `${header}\n${state.job.id}     cpu        degu-first-job  ${status}`;
}

function jobRecord(state) {
  return `JobId=${state.job.id} UserId=demo(1000)\nJobState=PENDING Reason=${state.job.reason}\nPartition=cpu NumNodes=${state.requestedNodes}\nCPUs/Task=${CLUSTER.cpuPerTask} TimeLimit=${CLUSTER.walltime}`;
}
