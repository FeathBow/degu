import { t } from './i18n/index.js';
import { icon } from './ui/helpers.js';

const STORAGE_KEY = 'degu.adventure.preferences.v1';
const THEME_COLORS = Object.freeze({ light: '#f7f7ef', dark: '#152019' });

export function preferenceControls() {
  return `<div class="preferences">
    <label class="preference-control"><span class="sr-only">${t('Language')}</span>
      <select id="language-select" data-focus-key="language" aria-label="${t('Language')}">
        <option value="en" lang="en">English</option><option value="zh-CN" lang="zh-CN">简体中文</option></select>
      <span class="select-chevron" aria-hidden="true">${icon('chevron')}</span></label>
    <label class="preference-control appearance-control"><span class="appearance-icon" aria-hidden="true">${icon('sun')}</span>
      <span class="sr-only">${t('Appearance')}</span><select id="appearance-select" data-focus-key="appearance" aria-label="${t('Appearance')}">
        <option value="system">${t('System')}</option><option value="light">${t('Light')}</option><option value="dark">${t('Dark')}</option></select>
      <span class="select-chevron" aria-hidden="true">${icon('chevron')}</span></label></div>`;
}

export function syncPreferences() {
  const root = document.documentElement;
  document.querySelector('#language-select').value = root.lang;
  document.querySelector('#appearance-select').value = root.dataset.appearance;
  document.querySelector('.appearance-icon').innerHTML = icon(root.dataset.theme === 'dark' ? 'moon' : 'sun');
  document.querySelector('meta[name="theme-color"]').content = THEME_COLORS[root.dataset.theme];
  document.querySelector('meta[name="description"]').content = t('Send a little job through Slurm, read its result, and make room for your next experiment. A playful, interactive HPC adventure with degu.');
  document.querySelector('.skip-link').textContent = t('Skip to the tutorial');
  document.title = t('degu’s little HPC adventure');
}

export function bindPreferences(options) {
  const { refresh, onError } = options;
  const media = matchMedia('(prefers-color-scheme: dark)');
  document.addEventListener('change', (event) => {
    if (!['language-select', 'appearance-select'].includes(event.target.id)) return;
    try {
      const root = document.documentElement;
      const next = { language: root.lang, appearance: root.dataset.appearance,
        [event.target.id === 'language-select' ? 'language' : 'appearance']: event.target.value };
      savePreferences(next);
      root.lang = next.language;
      root.dataset.appearance = next.appearance;
      root.dataset.theme = next.appearance === 'system' ? (media.matches ? 'dark' : 'light') : next.appearance;
      refresh();
    } catch (error) { onError(error); }
  });
  media.addEventListener('change', () => {
    if (document.documentElement.dataset.appearance !== 'system') return;
    document.documentElement.dataset.theme = media.matches ? 'dark' : 'light';
    syncPreferences();
  });
}

function savePreferences(preferences) {
  if (!['en', 'zh-CN'].includes(preferences.language) || !['system', 'light', 'dark'].includes(preferences.appearance)) {
    throw new Error('Invalid tutorial preference selection.');
  }
  localStorage.setItem(STORAGE_KEY, JSON.stringify(preferences));
}
