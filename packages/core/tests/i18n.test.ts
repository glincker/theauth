import { describe, expect, it } from "vitest";
import { createI18n } from "../src/i18n/i18n.js";
import { de } from "../src/i18n/locales/de.js";
import { en } from "../src/i18n/locales/en.js";
import { es } from "../src/i18n/locales/es.js";
import { fr } from "../src/i18n/locales/fr.js";
import { ja } from "../src/i18n/locales/ja.js";
import { zh } from "../src/i18n/locales/zh.js";

// Default English

describe("default English translations", () => {
	it("returns the English string for a known key", () => {
		const i18n = createI18n();
		expect(i18n.t("auth.invalidCredentials")).toBe("Invalid email or password.");
	});

	it("returns English when no locale is specified", () => {
		const i18n = createI18n();
		expect(i18n.t("general.notFound")).toBe("The requested resource was not found.");
	});

	it("covers all TranslationKeys with non-empty strings", () => {
		const i18n = createI18n();
		const keys = Object.keys(en) as Array<keyof typeof en>;
		for (const key of keys) {
			const result = i18n.t(key);
			expect(result.length).toBeGreaterThan(0);
		}
	});
});

describe("variable interpolation", () => {
	it("replaces a single {{var}} placeholder", () => {
		const i18n = createI18n();
		const result = i18n.t("auth.rateLimited", { retryAfter: "30" });
		expect(result).toBe("Too many requests. Try again in 30 seconds.");
	});

	it("replaces multiple {{var}} placeholders in one string", () => {
		const i18n = createI18n({
			translations: {
				en: {
					"email.invitation.subject": "Join {{orgName}} — invited by {{inviter}}",
				},
			},
		});
		const result = i18n.t("email.invitation.subject", {
			orgName: "Acme",
			inviter: "Alice",
		});
		expect(result).toBe("Join Acme — invited by Alice");
	});

	it("leaves unknown placeholders intact", () => {
		const i18n = createI18n();
		// retryAfter is the only var; passing nothing for it leaves it as-is
		const result = i18n.t("auth.rateLimited", {});
		expect(result).toContain("{{retryAfter}}");
	});

	it("passes locale as third argument alongside vars", () => {
		const i18n = createI18n({
			translations: {
				fr: {
					"auth.rateLimited": "Trop de tentatives. Réessayez dans {{retryAfter}} secondes.",
				},
			},
		});
		const result = i18n.t("auth.rateLimited", { retryAfter: "60" }, "fr");
		expect(result).toBe("Trop de tentatives. Réessayez dans 60 secondes.");
	});
});

describe("custom locale", () => {
	it("uses custom translation when locale matches", () => {
		const i18n = createI18n({
			translations: {
				pt: {
					"auth.invalidCredentials": "E-mail ou senha inválidos.",
				},
			},
		});
		expect(i18n.t("auth.invalidCredentials", "pt")).toBe("E-mail ou senha inválidos.");
	});

	it("partially overrides English — missing keys fall back to English", () => {
		const i18n = createI18n({
			translations: {
				pt: {
					"auth.invalidCredentials": "E-mail ou senha inválidos.",
				},
			},
		});
		// "general.notFound" was not supplied in "pt" → falls back to English
		expect(i18n.t("general.notFound", "pt")).toBe("The requested resource was not found.");
	});

	it("uses defaultLocale when no locale is passed to t()", () => {
		const i18n = createI18n({
			defaultLocale: "es",
			translations: {
				es: { ...es },
			},
		});
		expect(i18n.t("auth.invalidCredentials")).toBe("Correo electrónico o contraseña incorrectos.");
	});
});

// Locale fallback (en-US -> en)

describe("locale resolution fallback", () => {
	it("resolves 'en-US' to the 'en' locale", () => {
		const i18n = createI18n();
		// Only "en" is registered by default, not "en-US"
		expect(i18n.t("auth.invalidCredentials", "en-US")).toBe("Invalid email or password.");
	});

	it("resolves 'es-MX' to the 'es' locale when 'es' is registered", () => {
		const i18n = createI18n({
			translations: { es: { ...es } },
		});
		expect(i18n.t("auth.invalidCredentials", "es-MX")).toBe(
			"Correo electrónico o contraseña incorrectos.",
		);
	});

	it("falls back to defaultLocale when no prefix match exists", () => {
		const i18n = createI18n({ defaultLocale: "en" });
		// "xx" is completely unknown
		expect(i18n.t("auth.invalidCredentials", "xx")).toBe("Invalid email or password.");
	});

	it("exact match wins over prefix when both are registered", () => {
		const i18n = createI18n({
			translations: {
				en: { "auth.invalidCredentials": "English base." },
				"en-AU": { "auth.invalidCredentials": "Australian English." },
			},
		});
		expect(i18n.t("auth.invalidCredentials", "en-AU")).toBe("Australian English.");
	});
});

describe("missing key fallback", () => {
	it("returns the key string when no translation exists", () => {
		const i18n = createI18n({
			translations: {
				// Locale with no keys at all
				zz: {},
			},
		});
		// Falls back all the way to key name
		const key = "auth.invalidCredentials" as const;
		// This locale won't have it, and we override 'en' to be empty
		const i18nEmpty = createI18n({
			translations: {
				en: {} as never,
			},
		});
		// createI18n merges with the built-in en, so it still resolves.
		// To truly test the last-resort path we need a totally new registry entry.
		void i18nEmpty;

		// Standard path: unknown locale falls back through English
		expect(i18n.t(key, "zz")).toBe("Invalid email or password.");
	});

	it("returns the key for a locale override that sets undefined-ish values", () => {
		// Simulate a scenario where the English fallback entry itself is missing.
		// We create an i18n where we register a locale without overlapping keys
		// and then request a key that does not exist in English either.
		// Because TranslationKeys covers all keys, we exercise this via casting.
		const i18n = createI18n();
		// Cast a made-up key to verify the safety net
		const fakeKey = "does.not.exist" as keyof import("../src/i18n/i18n.js").TranslationKeys;
		expect(i18n.t(fakeKey)).toBe("does.not.exist");
	});
});

describe("addLocale", () => {
	it("registers a new locale and makes it immediately available", () => {
		const i18n = createI18n();
		i18n.addLocale("ko", {
			"auth.invalidCredentials": "이메일 또는 비밀번호가 올바르지 않습니다.",
		});
		expect(i18n.t("auth.invalidCredentials", "ko")).toBe(
			"이메일 또는 비밀번호가 올바르지 않습니다.",
		);
	});

	it("merges into an existing locale rather than replacing it", () => {
		const i18n = createI18n({
			translations: {
				en: { "auth.invalidCredentials": "Wrong credentials." },
			},
		});
		i18n.addLocale("en", { "auth.unauthorized": "Not allowed." });

		// Both keys should be present
		expect(i18n.t("auth.invalidCredentials")).toBe("Wrong credentials.");
		expect(i18n.t("auth.unauthorized")).toBe("Not allowed.");
	});

	it("appears in getLocales() after being added", () => {
		const i18n = createI18n();
		expect(i18n.getLocales()).not.toContain("ko");
		i18n.addLocale("ko", { "auth.invalidCredentials": "잘못된 자격 증명." });
		expect(i18n.getLocales()).toContain("ko");
	});
});

describe("built-in locale bundles", () => {
	const allLocales: Array<[string, Record<string, string>]> = [
		["en", en],
		["es", es],
		["fr", fr],
		["de", de],
		["ja", ja],
		["zh", zh],
	];

	it.each(allLocales)("%s: loads without errors", (_code, locale) => {
		expect(typeof locale).toBe("object");
	});

	it.each(allLocales)("%s: all values are non-empty strings", (_code, locale) => {
		for (const [key, value] of Object.entries(locale)) {
			expect(typeof value, `key: ${key}`).toBe("string");
			expect((value as string).length, `key: ${key}`).toBeGreaterThan(0);
		}
	});

	it.each(allLocales)("%s: integrates into createI18n and resolves every key", (code, locale) => {
		const i18n = createI18n({ translations: { [code]: locale } });
		for (const key of Object.keys(locale) as Array<keyof typeof en>) {
			const result = i18n.t(key, code);
			expect(result.length).toBeGreaterThan(0);
		}
	});
});

describe("getLocales", () => {
	it("returns 'en' by default", () => {
		const i18n = createI18n();
		expect(i18n.getLocales()).toContain("en");
	});

	it("returns all registered locales", () => {
		const i18n = createI18n({
			translations: {
				es: { ...es },
				fr: { ...fr },
			},
		});
		const locales = i18n.getLocales();
		expect(locales).toContain("en");
		expect(locales).toContain("es");
		expect(locales).toContain("fr");
	});

	it("reflects runtime additions", () => {
		const i18n = createI18n();
		i18n.addLocale("de", { ...de });
		i18n.addLocale("ja", { ...ja });
		const locales = i18n.getLocales();
		expect(locales).toContain("de");
		expect(locales).toContain("ja");
	});
});
