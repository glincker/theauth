import { computeConfidence } from "./confidence.js";
import { evaluateConsent } from "./consent.js";
import { DEFAULTS } from "./defaults.js";
import { randomToken } from "./encoding.js";
import { fail, ok, runSource } from "./result.js";
import { validatePayload } from "./schema.js";
import { toSignalV1 } from "./signal-v1.js";
import { automation } from "./sources/automation.js";
import { capabilities } from "./sources/capabilities.js";
import { clientHints } from "./sources/client-hints.js";
import { hardware } from "./sources/hardware.js";
import { languages } from "./sources/languages.js";
import { preferences } from "./sources/preferences.js";
import { screenSource } from "./sources/screen.js";
import { timezone } from "./sources/timezone.js";
import { touch } from "./sources/touch.js";
import type {
	CollectOptions,
	Components,
	Flags,
	Result,
	SignalV1,
	UnavailableName,
	VisitorSignalPayload,
} from "./types.js";

const UNAVAILABLE_CHECKS: ReadonlyArray<[UnavailableName, (c: Components) => boolean]> = [
	["tz", (c) => c.tz === undefined],
	["lang", (c) => c.lang === undefined],
	["platform", (c) => c.platform === undefined],
	["ua", (c) => c.uaBrand === undefined && c.uaMajor === undefined],
	["screen", (c) => c.screenBucket === undefined],
	["touch", (c) => c.touchPoints === undefined],
	["cores", (c) => c.cores === undefined],
	["memory", (c) => c.memoryGb === undefined],
	["caps", (c) => c.caps === undefined],
];

/** Missing component keys become the schema's `unavailable` names. */
export const findUnavailable = (components: Components): UnavailableName[] =>
	UNAVAILABLE_CHECKS.filter(([, missing]) => missing(components)).map(([name]) => name);

const baseFlags = (): Flags => ({
	protectedBrowser: false,
	webdriver: false,
	headlessHint: false,
	inconsistent: false,
});

interface Built {
	payload: VisitorSignalPayload;
}

const build = async (options: CollectOptions): Promise<Result<Built>> => {
	if (options.mode !== "analytics") {
		return fail("mode_unsupported", "only analytics mode is implemented in this release");
	}
	const now = options.now ?? Date.now;
	const started = now();
	const nonce = options.nonce ?? randomToken(DEFAULTS.nonceLength);
	const head = { v: 1 as const, mode: options.mode, ts: started, nonce };
	const challenge = options.challenge === undefined ? {} : { challenge: options.challenge };

	const decision = await evaluateConsent(
		options.consent,
		options.consentTimeoutMs ?? DEFAULTS.consentTimeoutMs,
	);
	if (!decision.allowed) {
		const flags: Flags = { ...baseFlags(), dnt: decision.dnt, gpc: decision.gpc };
		return finish({
			...head,
			...challenge,
			status: "suppressed",
			suppressedReason: decision.reason,
			components: {},
			flags,
			collectMs: Math.max(0, now() - started),
		});
	}

	const timeout = options.sourceTimeoutMs ?? DEFAULTS.sourceTimeoutMs;
	const [tz, lang, scr, ua, tch, hw, caps, prefs, auto] = await Promise.all([
		runSource("timezone", timezone, timeout),
		runSource("languages", languages, timeout),
		runSource("screen", screenSource, timeout),
		runSource("client-hints", clientHints, timeout),
		runSource("touch", touch, timeout),
		runSource("hardware", hardware, timeout),
		runSource("capabilities", capabilities, timeout),
		runSource("preferences", preferences, timeout),
		runSource("automation", automation, timeout),
	]);
	const components: Components = {};
	for (const r of [tz, lang, scr, ua, tch, hw, caps, prefs]) {
		if (r.success) Object.assign(components, r.data);
	}
	const flags: Flags = baseFlags();
	if (auto.success) {
		flags.webdriver = auto.data.webdriver;
		flags.headlessHint = auto.data.headlessHint;
		flags.protectedBrowser = auto.data.protectedBrowser;
		flags.automationGlobals = auto.data.automationGlobals;
	}
	const unavailable = findUnavailable(components);
	return finish({
		...head,
		...challenge,
		status: unavailable.length > 0 ? "partial" : "ok",
		components,
		...(unavailable.length > 0 ? { unavailable } : {}),
		flags,
		collectMs: Math.max(0, now() - started),
	});
};

const finish = (payload: VisitorSignalPayload): Result<Built> => {
	const checked = validatePayload(payload);
	if (!checked.valid) return fail("invalid_payload", checked.errors.join("; "));
	return ok({ payload });
};

/** Collect after consent. Writes no storage, sets no cookies, makes no network calls. */
export const collect = async (options: CollectOptions): Promise<Result<VisitorSignalPayload>> => {
	const built = await build(options);
	return built.success ? ok(built.data.payload) : built;
};

/** Cookieless digest profile. Fails with code `suppressed` when consent or DNT/GPC blocks it. */
export const collectSignalV1 = async (options: CollectOptions): Promise<Result<SignalV1>> => {
	if (options.pepper === undefined || options.pepper === "") {
		return fail("pepper_required", "pepper is required for the SignalV1 profile");
	}
	const built = await build(options);
	if (!built.success) return built;
	const { payload } = built.data;
	if (payload.status === "suppressed") {
		return fail("suppressed", payload.suppressedReason ?? "suppressed");
	}
	const confidence = computeConfidence(payload, options.confidenceModel);
	const now = options.now ?? Date.now;
	return ok(await toSignalV1(payload.components, options.pepper, confidence, now()));
};
