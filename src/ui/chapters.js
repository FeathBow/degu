import { t } from '../i18n/index.js';

export const CHAPTERS = Object.freeze(['slurm', 'cleanup']);

export function chapterFromUrl(url) {
  const chapter = url.searchParams.get('chapter') ?? 'slurm';
  if (!CHAPTERS.includes(chapter)) throw new Error(`Unknown tutorial chapter: ${chapter}`);
  return chapter;
}

export function chapterNav(active) {
  const names = ['Run an experiment', 'Make room for the next'];
  return `<nav class="chapter-nav" aria-label="${t('Your adventure')}">${CHAPTERS.map((chapter, index) =>
    `<button data-chapter="${chapter}" data-focus-key="chapter-${chapter}" ${chapter === active ? 'aria-current="page"' : ''}>
      <span class="chapter-mark" data-chapter-mark="${chapter}">${index + 1}</span><span>${t(names[index])}</span></button>`).join('')}</nav>`;
}

export function updateChapterNav(options) {
  const { completed, busy } = options;
  for (const [index, chapter] of CHAPTERS.entries()) {
    const button = document.querySelector(`[data-chapter="${chapter}"]`);
    button.disabled = busy;
    button.classList.toggle('is-complete', completed[chapter]);
    const mark = button.querySelector('.chapter-mark');
    mark.textContent = completed[chapter] ? '✓' : String(index + 1);
    if (completed[chapter]) mark.setAttribute('aria-label', t('Completed chapter'));
    else mark.removeAttribute('aria-label');
  }
}
