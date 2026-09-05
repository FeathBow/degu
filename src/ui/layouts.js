import { art, icon } from './helpers.js';
import { sceneShell } from './scene.js';
import { t } from '../i18n/index.js';
import { preferenceControls } from '../preferences.js';
import { chapterNav } from './chapters.js';

export function layoutShell(scenario) {
  return `<div class="page layout-habitat">${navigation()}${hero()}${chapterNav('cleanup')}
    <main id="tutorial" data-phase="welcome">${habitat(scenario)}</main>${footer()}</div>`;
}

export function navigation() {
  return `<header class="nav"><div><a class="brand" href="https://github.com/FeathBow/degu" aria-label="${t('degu on GitHub')}">
      ${art('degu', 'brand-mark')}<span class="brand-name">degu</span></a><span class="brand-note">${t('Small tool. Thoughtful cleanup.')}</span></div>
    <nav class="nav-links" aria-label="${t('Project')}"><a href="https://github.com/FeathBow/degu/blob/main/docs/usage.md">${t('Docs')}</a>
      <a href="https://github.com/FeathBow/degu">GitHub ↗</a>
      <a class="nav-install" href="https://github.com/FeathBow/degu#installation">${t('Get degu')} <span aria-hidden="true">↗</span></a>${preferenceControls()}</nav></header>`;
}

export function hero() {
  return `<section class="hero"><div><div class="eyebrow">${art('leaf')} ${t('AN INTERACTIVE FIELD GUIDE')}</div>
    <h1>${t('A little room for <em>big ideas.</em>')}</h1></div>
    <p class="hero-description">${t('Your next experiment deserves the space.<br> Learn to clean your cache, <strong>with a little care.</strong>')}</p></section>`;
}

export function toolbar() {
  return `<div class="tutorial-toolbar"><span class="pill"><span class="pill-dot"></span> ${t('Browser simulation')}</span>
    <button class="text-button restart-button" data-action="reset" data-focus-key="restart-nav">${icon('reset')} ${t('Restart demo')}</button></div>`;
}

function lesson() {
  return `<section id="lesson" class="lesson-panel" tabindex="-1" aria-label="${t('Your tutorial step')}"></section>`;
}

function terminalSlot() {
  return `<section id="terminal-slot" class="terminal" aria-label="${t('Corresponding degu command')}"></section>`;
}

function habitat(scenario) {
  return `${toolbar()}<div class="habitat-grid">${lesson()}
    <div class="world-column"><section id="quota-slot" class="quota-panel" aria-label="${t('Quota')}"></section>${sceneShell(scenario)}</div></div>
    <div id="journey-slot" class="journey"></div>${terminalSlot()}`;
}

export function footer(options = {}) {
  return `<footer class="footer"><span>${t('Made for your terminal. Explained with a little degu.')}<br>
      ${t(options.detail ?? 'Sample ext4 HOME · No real files are accessed.')}</span><div id="activity-slot" class="activity-link"></div>
    <div class="footer-links"><a href="https://github.com/FeathBow/degu/blob/main/docs/usage.md">${t('Docs')}</a>
      <a href="https://github.com/FeathBow/degu">GitHub ↗</a>
      <a href="https://github.com/FeathBow/degu/blob/main/docs/safety.md">${t('How degu keeps you in control')} ↗</a></div></footer>`;
}
