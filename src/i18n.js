import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join, basename } from 'node:path';
import { fileURLToPath } from 'node:url';
import i18next from 'i18next';

const here = dirname(fileURLToPath(import.meta.url));
const localesDir = join(here, '..', 'locales');

// Canonical BCP-47 casing for i18next ('de-de' file -> 'de-DE' resource).
// i18next matches region subtags case-sensitively, so all-lowercase keys
// like 'de-de' never resolve.
function canonical(lng) {
  const parts = String(lng).toLowerCase().replace(/_/g, '-').split('-');
  if (parts.length === 1) return parts[0];
  return `${parts[0]}-${parts.slice(1).join('-').toUpperCase()}`;
}

// Language codes match locale filenames (e.g. locales/de-de.json -> 'de-DE').
export const SUPPORTED_LOCALES = [];
const resources = {};
// Lowercase filename -> canonical code, for resolving Telegram tags.
const byLower = {};
for (const file of readdirSync(localesDir)) {
  if (!file.endsWith('.json')) continue;
  const raw = basename(file, '.json');
  const lng = canonical(raw);
  try {
    resources[lng] = {
      translation: JSON.parse(readFileSync(join(localesDir, file), 'utf8')),
    };
    byLower[raw.toLowerCase()] = lng;
    byLower[lng.toLowerCase()] = lng;
    SUPPORTED_LOCALES.push(lng);
  } catch {
    // Skip unreadable locale files; 'en' fallback remains.
  }
}
if (!SUPPORTED_LOCALES.includes('en')) SUPPORTED_LOCALES.unshift('en');
SUPPORTED_LOCALES.sort((a, b) =>
  a === 'en' ? -1 : b === 'en' ? 1 : a.localeCompare(b),
);

export const LANGUAGE_NAMES = {
  en: 'English',
  'de-DE': 'Deutsch',
  es: 'Español',
  fr: 'Français',
  it: 'Italiano',
  'pt-BR': 'Português (BR)',
  ru: 'Русский',
  sv: 'Svenska',
};
// Lowercase aliases (callback data, Telegram tags) -> canonical codes.
for (const [k, v] of Object.entries({ ...LANGUAGE_NAMES })) {
  LANGUAGE_NAMES[k.toLowerCase()] ??= v;
}

// Map Telegram/BCP-47 tags (de, de-DE, pt_BR, ...) onto our locale resources.
export function normalizeLocale(tag) {
  if (!tag) return 'en';
  const lower = String(tag).toLowerCase().replace(/_/g, '-');
  if (byLower[lower]) return byLower[lower];
  if (resources[canonical(tag)]) return canonical(tag);
  const base = lower.split('-')[0];
  if (byLower[base]) return byLower[base];
  if (resources[base]) return base;
  // Aliases for locales shipped with a region suffix.
  if (base === 'de' && byLower['de-de']) return byLower['de-de'];
  if (base === 'pt' && byLower['pt-br']) return byLower['pt-br'];
  return 'en';
}

export function isSupportedLocale(tag) {
  if (!tag) return false;
  const lower = String(tag).toLowerCase().replace(/_/g, '-');
  return Boolean(byLower[lower] || byLower[lower.split('-')[0]]);
}

// HTML is built by callers (user input is escaped before interpolation),
// so must not escape values here.
await i18next.init({
  lng: 'en',
  fallbackLng: 'en',
  resources,
  interpolation: { escapeValue: false },
});

export const t = (key, options) => i18next.t(key, options);

// Per-user translator for languages: tFor('es')('balance.value', ...)
export const tFor = lng => (key, options) =>
  i18next.t(key, { ...options, lng: normalizeLocale(lng) });

export async function addLocale(lng, translations) {
  i18next.addResourceBundle(canonical(lng), 'translation', translations, true, true);
}

export default i18next;
