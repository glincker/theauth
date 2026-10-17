export type { I18nConfig, I18nModule, TranslationKeys } from "./i18n.js";
export { createI18n } from "./i18n.js";
export { de } from "./locales/de.js";
// Built-in locale bundles, exported for tree-shaking.
// Consumers only pay for the locales they import.
export { en } from "./locales/en.js";
export { es } from "./locales/es.js";
export { fr } from "./locales/fr.js";
export { ja } from "./locales/ja.js";
export { zh } from "./locales/zh.js";
