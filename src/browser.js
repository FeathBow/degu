import { t } from './i18n/index.js';

export const browserClock = Object.freeze({
  now: () => new Date().toISOString(),
  wait: (duration) => new Promise((resolve) => setTimeout(resolve, duration)),
  reducedMotion: () => matchMedia('(prefers-reduced-motion: reduce)').matches,
});

export async function copyCommand(root) {
  const command = root.querySelector('[data-command]').textContent;
  const feedback = root.querySelector('#copy-feedback');
  try {
    await navigator.clipboard.writeText(command);
    feedback.textContent = t('Copied');
  } catch (error) {
    feedback.textContent = t('Copy failed. Select the command to copy it manually.');
    console.error('Command copy failed.', error);
  }
}

export function downloadReceipt(receipt) {
  const blob = new Blob([`${JSON.stringify(receipt, null, 2)}\n`], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = 'degu-demo-receipt.json';
  document.body.append(link);
  link.click();
  link.remove();
  const DOWNLOAD_URL_LIFETIME_MS = 1000;
  setTimeout(() => URL.revokeObjectURL(url), DOWNLOAD_URL_LIFETIME_MS);
}

export function reportError(error) {
  const banner = document.querySelector('#error-banner');
  banner.hidden = false;
  banner.textContent = t('The tutorial stopped on an error: {message}. Restart the page to begin again.', { message: error.message });
  console.error(error);
}
