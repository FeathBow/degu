import { ZH } from './zh.js';
import { SCENARIO_ZH } from './scenario-zh.js';
import { SLURM_ZH } from './slurm-zh.js';

const CHINESE = Object.freeze({ ...ZH, ...SCENARIO_ZH, ...SLURM_ZH });

export function t(source, values = {}, locale = document.documentElement.lang) {
  if (!['en', 'zh-CN'].includes(locale)) throw new Error(`Unsupported language: ${locale}`);
  if (locale === 'zh-CN' && !Object.hasOwn(CHINESE, source)) throw new Error(`Missing Chinese translation: ${source}`);
  const template = locale === 'en' ? source : CHINESE[source];
  return template.replace(/\{(\w+)\}/g, (_, key) => {
    if (!Object.hasOwn(values, key)) throw new Error(`Missing translation value: ${key}`);
    return String(values[key]);
  });
}
