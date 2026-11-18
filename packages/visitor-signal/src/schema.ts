/** Hand validator mirroring schema/v1.json. Returns every violation it finds. */
export interface ValidationResult {
	valid: boolean;
	errors: string[];
}

type Obj = Record<string, unknown>;

const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);
const isInt = (v: unknown, min: number, max: number): boolean =>
	typeof v === "number" && Number.isInteger(v) && v >= min && v <= max;
/** Length in code points, so it agrees with rune counts on the Go side. */
const cpLen = (s: string): number => [...s].length;
const isStr = (v: unknown, max: number): boolean => typeof v === "string" && cpLen(v) <= max;

const COMPONENT_RULES = new Map<string, (v: unknown) => boolean>(
	Object.entries({
		tz: (v) => isStr(v, 64),
		tzOffsetMin: (v) => isInt(v, -840, 840),
		lang: (v) => isStr(v, 35),
		langCount: (v) => isInt(v, 0, 20),
		platform: (v) => isStr(v, 32),
		uaBrand: (v) => isStr(v, 32),
		uaMajor: (v) => isInt(v, 0, 999),
		mobile: (v) => typeof v === "boolean",
		screenBucket: (v) =>
			typeof v === "string" && /^[1-9][0-9]{0,2}00x[1-9][0-9]{0,2}00@[0-9](\.[0-9])?$/.test(v),
		colorDepth: (v) => [16, 24, 30, 32, 48].includes(v as number),
		touchPoints: (v) => isInt(v, 0, 10),
		cores: (v) => [1, 2, 4, 8, 16, 32, 64].includes(v as number),
		memoryGb: (v) => [0.25, 0.5, 1, 2, 4, 8].includes(v as number),
		reducedMotion: (v) => typeof v === "boolean",
		colorScheme: (v) => v === "light" || v === "dark" || v === "none",
		caps: (v) => isInt(v, 0, 4294967295),
		renderHash: (v) => typeof v === "string" && /^[0-9a-f]{16}$/.test(v),
	}),
);

const UNAVAILABLE = [
	"tz",
	"lang",
	"platform",
	"ua",
	"screen",
	"touch",
	"cores",
	"memory",
	"caps",
	"renderHash",
];
const REASONS = ["consent_denied", "consent_unknown", "dnt", "gpc", "route_not_protected"];
const TOP = [
	"v",
	"mode",
	"status",
	"suppressedReason",
	"ts",
	"nonce",
	"challenge",
	"components",
	"unavailable",
	"flags",
	"collectMs",
];
const FLAG_BOOL = [
	"protectedBrowser",
	"webdriver",
	"headlessHint",
	"inconsistent",
	"noInputObserved",
	"dnt",
	"gpc",
];
const FLAG_REQUIRED = ["protectedBrowser", "webdriver", "headlessHint", "inconsistent"];

const checkFlags = (flags: unknown, errors: string[]): void => {
	if (!isObj(flags)) {
		errors.push("flags: required object");
		return;
	}
	for (const k of FLAG_REQUIRED) if (!Object.hasOwn(flags, k)) errors.push(`flags.${k}: required`);
	for (const [k, v] of Object.entries(flags)) {
		if (FLAG_BOOL.includes(k)) {
			if (typeof v !== "boolean") errors.push(`flags.${k}: boolean`);
		} else if (k === "automationGlobals") {
			if (!isInt(v, 0, 32)) errors.push("flags.automationGlobals: integer 0..32");
		} else errors.push(`flags.${k}: unknown field`);
	}
};

export const validatePayload = (input: unknown): ValidationResult => {
	const errors: string[] = [];
	if (!isObj(input)) return { valid: false, errors: ["payload: object required"] };
	for (const k of ["v", "mode", "ts", "nonce", "status", "components", "flags"]) {
		if (!(k in input)) errors.push(`${k}: required`);
	}
	for (const k of Object.keys(input)) if (!TOP.includes(k)) errors.push(`${k}: unknown field`);
	if (Object.hasOwn(input, "v") && input.v !== 1) errors.push("v: must be 1");
	if (
		Object.hasOwn(input, "mode") &&
		input.mode !== "analytics" &&
		input.mode !== "fraud_prevention"
	)
		errors.push("mode: enum");
	const status = input.status;
	if (
		Object.hasOwn(input, "status") &&
		status !== "ok" &&
		status !== "suppressed" &&
		status !== "partial"
	)
		errors.push("status: enum");
	if (Object.hasOwn(input, "ts") && !isInt(input.ts, 0, Number.MAX_SAFE_INTEGER))
		errors.push("ts: integer >= 0");
	if (Object.hasOwn(input, "nonce")) {
		const n = input.nonce;
		if (typeof n !== "string" || n.length < 16 || n.length > 64 || !/^[A-Za-z0-9_-]+$/.test(n))
			errors.push("nonce: 16..64 base64url chars");
	}
	if (Object.hasOwn(input, "challenge") && !isStr(input.challenge, 2048))
		errors.push("challenge: string max 2048");
	if (Object.hasOwn(input, "collectMs") && !isInt(input.collectMs, 0, 60000))
		errors.push("collectMs: integer 0..60000");
	if (
		Object.hasOwn(input, "suppressedReason") &&
		!REASONS.includes(input.suppressedReason as string)
	)
		errors.push("suppressedReason: enum");
	if (Object.hasOwn(input, "unavailable")) {
		const u = input.unavailable;
		if (
			!Array.isArray(u) ||
			u.some((x) => !UNAVAILABLE.includes(x as string)) ||
			new Set(u).size !== u.length
		)
			errors.push("unavailable: unique enum array");
	}
	if (Object.hasOwn(input, "flags")) checkFlags(input.flags, errors);
	const comps = input.components;
	if (Object.hasOwn(input, "components")) {
		if (!isObj(comps)) errors.push("components: object required");
		else {
			for (const [k, v] of Object.entries(comps)) {
				const rule = COMPONENT_RULES.get(k);
				if (!rule) errors.push(`components.${k}: unknown field`);
				else if (!rule(v)) errors.push(`components.${k}: invalid value`);
			}
			if (input.mode === "analytics" && Object.hasOwn(comps, "renderHash"))
				errors.push("components.renderHash: fraud_prevention only");
			if (status === "suppressed" && Object.keys(comps).length > 0)
				errors.push("components: must be empty when suppressed");
		}
	}
	if (status === "suppressed") {
		if (!Object.hasOwn(input, "suppressedReason"))
			errors.push("suppressedReason: required when suppressed");
	} else if (Object.hasOwn(input, "suppressedReason"))
		errors.push("suppressedReason: only allowed when suppressed");
	return { valid: errors.length === 0, errors };
};
