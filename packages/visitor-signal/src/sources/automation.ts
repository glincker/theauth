import { DEFAULTS } from "../defaults.js";
import { ok } from "../result.js";
import type { Result } from "../types.js";

export interface AutomationData {
	webdriver: boolean;
	headlessHint: boolean;
	automationGlobals: number;
	protectedBrowser: boolean;
}

/** Well-known globals injected by common automation drivers. */
export const AUTOMATION_GLOBALS: readonly string[] = [
	"__nightmare",
	"_phantom",
	"callPhantom",
	"__selenium_unwrapped",
	"__webdriver_evaluate",
	"__driver_evaluate",
	"__webdriver_script_fn",
	"domAutomation",
	"domAutomationController",
	"_Selenium_IDE_Recorder",
	"cdc_adoQpoasnfa76pfcZLmcfl_Array",
	"__playwright",
	"__pwInitScripts",
	"__pw_manual",
];

/** Rounded or fixed values are what resist-fingerprinting modes produce. */
export const looksProtected = (input: {
	width: number;
	height: number;
	innerWidth?: number;
	innerHeight?: number;
	hardwareConcurrency?: number;
	timezoneOffset: number;
}): boolean => {
	const letterboxed =
		input.innerWidth !== undefined &&
		input.innerHeight !== undefined &&
		input.innerWidth % 200 === 0 &&
		input.innerHeight % 100 === 0 &&
		input.width === input.innerWidth;
	const fixedCores = input.hardwareConcurrency === 2;
	return letterboxed && fixedCores && input.timezoneOffset === 0;
};

export const automation = async (): Promise<Result<AutomationData>> => {
	const nav = globalThis.navigator;
	const win = globalThis as unknown as Record<string, unknown>;
	const webdriver = nav?.webdriver === true;
	const found = AUTOMATION_GLOBALS.filter((name) => name in win).length;
	const ua = nav?.userAgent ?? "";
	const headlessHint =
		/HeadlessChrome/i.test(ua) ||
		(/Chrome\//.test(ua) && nav !== undefined && nav.languages?.length === 0);
	const scr = globalThis.screen;
	const protectedBrowser = scr
		? looksProtected({
				width: scr.width,
				height: scr.height,
				innerWidth: globalThis.innerWidth,
				innerHeight: globalThis.innerHeight,
				hardwareConcurrency: nav?.hardwareConcurrency,
				timezoneOffset: new Date().getTimezoneOffset(),
			})
		: false;
	return ok({
		webdriver,
		headlessHint,
		automationGlobals: Math.min(DEFAULTS.maxAutomationGlobals, found),
		protectedBrowser,
	});
};
