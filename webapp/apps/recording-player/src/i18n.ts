import i18next, { TOptions } from 'i18next';
import { GatewayAccessApi } from './gateway';

// Type definitions for translations
export type TranslationKeys =
  | 'notifications.streamingFinished'
  | 'notifications.internalError'
  | 'notifications.unauthorized'
  | 'notifications.unknownError'
  | 'notifications.protocolError'
  | 'ui.close';

/**
 * A branded type for translated strings.
 * This type ensures that only strings returned by the t() function can be used where translations are required.
 * The __brand property is never actually added to the string - it only exists at compile time.
 *
 * Example:
 * const str: string = "hello";
 * showNotification(str, 'success'); // ❌ Type error
 * showNotification(str as TranslatedString, 'success'); // ❌ Type error
 * showNotification(t('notifications.success'), 'success'); // ✅ OK
 */
export type TranslatedString = string & { readonly __brand: 'translated' };

export const setupI18n = async (gatewayApi: GatewayAccessApi, language?: string) => {
  // Get language from URL or browser settings
  const supportedLanguages = ['en', 'fr', 'de', 'es'];
  const browserLang = navigator.language.split('-')[0];
  const detectedLang = language || (supportedLanguages.includes(browserLang) ? browserLang : 'en');

  await i18next.init({
    lng: detectedLang,
    fallbackLng: 'en',
    debug: import.meta.env.MODE === 'development',
    resources: {
      en: {
        translation: await fetch(gatewayApi.playerResourceUrl('locales/en/translation.json')).then((r) => r.json()),
      },
      fr: {
        translation: await fetch(gatewayApi.playerResourceUrl('locales/fr/translation.json')).then((r) => r.json()),
      },
      de: {
        translation: await fetch(gatewayApi.playerResourceUrl('locales/de/translation.json')).then((r) => r.json()),
      },
      es: {
        translation: await fetch(gatewayApi.playerResourceUrl('locales/es/translation.json')).then((r) => r.json()),
      },
    },
  });

  return i18next;
};

// Helper function to translate text with type safety
export const t = (key: TranslationKeys, options?: TOptions): TranslatedString =>
  i18next.t(key, options) as TranslatedString;
