(() => {
  const STORAGE_KEY = 'degu.adventure.preferences.v1';
  const root = document.documentElement;
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    const preferences = stored === null
      ? { language: navigator.language.startsWith('zh') ? 'zh-CN' : 'en', appearance: 'system' }
      : JSON.parse(stored);
    if (!preferences || !['en', 'zh-CN'].includes(preferences.language)
      || !['system', 'light', 'dark'].includes(preferences.appearance)) {
      throw new Error('Invalid saved tutorial preferences.');
    }
    root.lang = preferences.language;
    root.dataset.appearance = preferences.appearance;
    root.dataset.theme = preferences.appearance === 'system'
      ? (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light') : preferences.appearance;
  } catch (error) {
    root.dataset.preferenceError = error.message;
    console.error('Tutorial preferences could not be loaded.', error);
  }
})();
