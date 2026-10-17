import { en } from "./locales/en.js";

export interface TranslationKeys {
	"auth.invalidCredentials": string;
	"auth.emailNotVerified": string;
	"auth.accountLocked": string;
	"auth.rateLimited": string;
	"auth.emailAlreadyExists": string;
	"auth.weakPassword": string;
	"auth.tokenExpired": string;
	"auth.tokenInvalid": string;
	"auth.unauthorized": string;

	"agent.notFound": string;
	"agent.revoked": string;
	"agent.limitExceeded": string;
	"agent.permissionDenied": string;

	"twoFactor.invalidCode": string;
	"twoFactor.alreadyEnabled": string;
	"twoFactor.notEnabled": string;

	"email.verification.subject": string;
	"email.passwordReset.subject": string;
	"email.magicLink.subject": string;
	"email.otp.subject": string;
	"email.invitation.subject": string;
	"email.welcome.subject": string;

	"general.serverError": string;
	"general.badRequest": string;
	"general.notFound": string;
}

export interface I18nConfig {
	/** Default locale (default: "en") */
	defaultLocale?: string;
	/** Custom translations merged on top of built-in defaults */
	translations?: Record<string, Partial<TranslationKeys>>;
}

export interface I18nModule {
	/** Get a translated string, optionally for a specific locale */
	t(key: keyof TranslationKeys, locale?: string): string;
	/** Get a translated string with variable interpolation */
	t(key: keyof TranslationKeys, vars: Record<string, string>, locale?: string): string;
	/** Add or replace translations for a locale at runtime */
	addLocale(locale: string, translations: Partial<TranslationKeys>): void;
	/** Return all registered locale codes */
	getLocales(): string[];
}

function interpolate(template: string, vars: Record<string, string>): string {
	return template.replace(/\{\{(\w+)\}\}/g, (match, key: string): string => {
		return Object.hasOwn(vars, key) ? (vars[key] ?? match) : `{{${key}}}`;
	});
}

/**
 * Resolve the best matching locale from the registry.
 * "en" when "en-US" is not registered) 3. Default locale 4.
 */
function resolveLocale(
	requested: string,
	registry: Map<string, Partial<TranslationKeys>>,
	defaultLocale: string,
): string {
	if (registry.has(requested)) return requested;

	const prefix = requested.split("-")[0];
	if (prefix && registry.has(prefix)) return prefix;

	if (registry.has(defaultLocale)) return defaultLocale;

	return "en";
}

export function createI18n(config: I18nConfig = {}): I18nModule {
	const defaultLocale = config.defaultLocale ?? "en";

	// Single Map, reads never mutate it (addLocale replaces the entry).
	const registry = new Map<string, Partial<TranslationKeys>>();

	// Always seed English built-ins first.
	registry.set("en", { ...en });

	// Merge any caller-supplied translations.
	if (config.translations) {
		for (const [locale, keys] of Object.entries(config.translations)) {
			const existing = registry.get(locale) ?? {};
			registry.set(locale, { ...existing, ...keys });
		}
	}

	function lookup(key: keyof TranslationKeys, locale: string): string {
		const resolved = resolveLocale(locale, registry, defaultLocale);
		const localeMap = registry.get(resolved);

		if (localeMap && key in localeMap) {
			return localeMap[key] as string;
		}

		// Fall back to English built-ins before returning the key itself.
		const englishMap = registry.get("en");
		if (englishMap && key in englishMap) {
			return englishMap[key] as string;
		}

		// Last resort: return the key so callers always get a string.
		return key;
	}

	function t(
		key: keyof TranslationKeys,
		varsOrLocale?: Record<string, string> | string,
		maybeLocale?: string,
	): string {
		if (typeof varsOrLocale === "string" || varsOrLocale === undefined) {
			// Overload: t(key, locale?)
			const locale = varsOrLocale ?? defaultLocale;
			return lookup(key, locale);
		}

		// Overload: t(key, vars, locale?)
		const locale = maybeLocale ?? defaultLocale;
		const raw = lookup(key, locale);
		return interpolate(raw, varsOrLocale);
	}

	function addLocale(locale: string, translations: Partial<TranslationKeys>): void {
		const existing = registry.get(locale) ?? {};
		registry.set(locale, { ...existing, ...translations });
	}

	function getLocales(): string[] {
		return Array.from(registry.keys());
	}

	return { t, addLocale, getLocales };
}
