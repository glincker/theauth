export type Result<T> =
	| { success: true; data: T }
	| { success: false; error: { code: string; message: string } };

export type Mode = "analytics" | "fraud_prevention";
export type Status = "ok" | "suppressed" | "partial";
export type ConsentState = "granted" | "denied" | "unknown";
export type SuppressedReason =
	| "consent_denied"
	| "consent_unknown"
	| "dnt"
	| "gpc"
	| "route_not_protected";
export type UnavailableName =
	| "tz"
	| "lang"
	| "platform"
	| "ua"
	| "screen"
	| "touch"
	| "cores"
	| "memory"
	| "caps"
	| "renderHash";

export interface Components {
	tz?: string;
	tzOffsetMin?: number;
	lang?: string;
	langCount?: number;
	platform?: string;
	uaBrand?: string;
	uaMajor?: number;
	mobile?: boolean;
	screenBucket?: string;
	colorDepth?: number;
	touchPoints?: number;
	cores?: number;
	memoryGb?: number;
	reducedMotion?: boolean;
	colorScheme?: "light" | "dark" | "none";
	caps?: number;
	renderHash?: string;
}

export interface Flags {
	protectedBrowser: boolean;
	webdriver: boolean;
	headlessHint: boolean;
	inconsistent: boolean;
	automationGlobals?: number;
	noInputObserved?: boolean;
	dnt?: boolean;
	gpc?: boolean;
}

export interface VisitorSignalPayload {
	v: 1;
	mode: Mode;
	status: Status;
	suppressedReason?: SuppressedReason;
	ts: number;
	nonce: string;
	challenge?: string;
	components: Components;
	unavailable?: UnavailableName[];
	flags: Flags;
	collectMs?: number;
}

export interface SignalV1 {
	v: 1;
	source: "browser";
	digest: string;
	confidence: number;
	components: number;
	ts: number;
}

export type ConsentHook = () => ConsentState | Promise<ConsentState>;

export interface CollectOptions {
	mode: Mode;
	consent: ConsentHook;
	/** Per-source timeout in ms. */
	sourceTimeoutMs?: number;
	/** Public per-site string for the SignalV1 digest. */
	pepper?: string;
	/** Route identifier; unused in analytics mode, reserved for fraud_prevention. */
	route?: string;
	/** Fixed nonce, mainly for tests and integrators that issue their own. */
	nonce?: string;
	/** Server challenge token to echo back. */
	challenge?: string;
	/** Clock override in epoch ms. */
	now?: () => number;
	/** Confidence model override. */
	confidenceModel?: Partial<ConfidenceModel>;
}

export interface ConfidenceModel {
	base: number;
	analyticsMode: number;
	mobileSafari: number;
	android: number;
	protectedBrowser: number;
	inconsistent: number;
	perUnavailable: number;
	unavailableCap: number;
	fewComponents: number;
	fewComponentsMin: number;
}
