/**
 * Authentication context of a session: which methods the user proved and when.
 *
 * This is the data behind step-up authentication (RFC 9470). A session records one event per
 * method (`password`, `totp`, `passkey`, ...). From those events the context derives:
 *
 * - `amr`, the Authentication Methods References of RFC 8176 (`pwd`, `otp`, `swk`, `user`, `mfa`)
 * - `acr`, an Authentication Context Class Reference chosen from the ordered list in {@link ACR}
 * - `authTime`, the time of the most recent event, in epoch seconds (OpenID Connect Core `auth_time`)
 *
 * The functions here are pure and use no Node APIs, so they run in any runtime.
 */

/** The ways a user can prove who they are. `passkey_presence` is a passkey assertion without user verification. */
export type AuthMethod = "password" | "totp" | "otp" | "passkey" | "passkey_presence" | "federated";

/** One authentication event. `at` is epoch seconds. */
export interface AuthEvent {
	method: AuthMethod;
	at: number;
	/**
	 * Methods an identity provider reported for a `federated` event (RFC 8176 `amr` values from its
	 * ID token). They are informational: they show up in the session `amr` but never raise `acr`,
	 * because theAuth cannot verify what the provider actually checked. `mfa` is dropped.
	 */
	idpAmr?: string[];
}

/**
 * Authentication context class references, weakest first. The values are opaque URNs to OAuth
 * clients (OpenID Connect Core section 2). Inside theAuth they are ordered: a stronger class
 * satisfies a request for a weaker one. That ordering is a theAuth rule, RFC 9470 itself
 * treats the values as opaque.
 */
export const ACR = {
	none: "urn:theauth:acr:none",
	singleFactor: "urn:theauth:acr:single-factor",
	mfa: "urn:theauth:acr:mfa",
	phishingResistant: "urn:theauth:acr:phishing-resistant",
} as const;

export type AcrValue = (typeof ACR)[keyof typeof ACR];

/** Every supported class, weakest first. Advertised as `acr_values_supported`. */
export const ACR_ORDER: readonly AcrValue[] = [
	ACR.none,
	ACR.singleFactor,
	ACR.mfa,
	ACR.phishingResistant,
];

/** Methods kept per session. One slot per method, so the list stays this short. */
const MAX_EVENTS = 8;

type Factor = "knowledge" | "possession" | "federated";

interface MethodTraits {
	amr: readonly string[];
	/** Factor category. A user verified passkey is both, so it carries `multi`. */
	factor: Factor;
	/** Highest class one fresh event of this method can vouch for. Index into `ACR_ORDER`. */
	tier: number;
	/** The single event is multi factor by itself (possession plus user verification). */
	multi: boolean;
}

const TRAITS: Record<AuthMethod, MethodTraits> = {
	password: { amr: ["pwd"], factor: "knowledge", tier: 1, multi: false },
	otp: { amr: ["otp"], factor: "possession", tier: 1, multi: false },
	totp: { amr: ["otp"], factor: "possession", tier: 2, multi: false },
	passkey_presence: { amr: ["swk", "user"], factor: "possession", tier: 1, multi: false },
	passkey: { amr: ["swk", "user"], factor: "possession", tier: 3, multi: true },
	// Signing in through an identity provider proves an account there. It rates as one factor, and a
	// theAuth code or passkey on top of it is a second, different category.
	federated: { amr: ["fed"], factor: "federated", tier: 1, multi: false },
};

/** RFC 8176 section 2 values a provider may report. `mfa` is excluded: theAuth derives it itself. */
const IDP_AMR_ALLOWED: ReadonlySet<string> = new Set([
	"face",
	"fpt",
	"geo",
	"hwk",
	"iris",
	"kba",
	"mca",
	"otp",
	"pin",
	"pwd",
	"rba",
	"retina",
	"sc",
	"sms",
	"swk",
	"tel",
	"user",
	"vbm",
	"wia",
]);

const MAX_IDP_AMR = 8;

/** Keep only registered RFC 8176 values, deduplicated and capped. Anything else from a provider is dropped. */
export function sanitizeIdpAmr(raw: unknown): string[] {
	if (!Array.isArray(raw)) return [];
	const out = new Set<string>();
	for (const value of raw) {
		if (typeof value === "string" && IDP_AMR_ALLOWED.has(value)) out.add(value);
		if (out.size >= MAX_IDP_AMR) break;
	}
	return [...out].sort();
}

/** The authentication methods a sign-in through the gate proves, by sign-in method name. Social sign-in records `federated`. One tap, SIWE and device sign-ins prove nothing theAuth can rate, so they record no event. */
export function authMethodsForSignIn(signIn: string): AuthMethod[] {
	switch (signIn) {
		case "password":
			return ["password"];
		case "magic_link":
		case "email_otp":
		case "phone":
			return ["otp"];
		case "passkey":
			return ["passkey_presence"];
		case "social":
			return ["federated"];
		default:
			return [];
	}
}

/** The derived view of a session's events. */
export interface AuthContext {
	/** RFC 8176 values, sorted, without duplicates. */
	amr: string[];
	acr: AcrValue;
	/** Epoch seconds of the most recent event, or of the session start when there are no events. */
	authTime: number;
	/** The raw events, newest first. */
	events: AuthEvent[];
}

export function isAuthMethod(value: unknown): value is AuthMethod {
	return typeof value === "string" && Object.hasOwn(TRAITS, value);
}

/** Keep only well formed events, newest first, one per method. Used on stored data, which is never trusted blindly. */
export function normalizeEvents(raw: unknown): AuthEvent[] {
	if (!Array.isArray(raw)) return [];
	const latest = new Map<AuthMethod, AuthEvent>();
	for (const item of raw) {
		if (typeof item !== "object" || item === null) continue;
		const { method, at, idpAmr } = item as { method?: unknown; at?: unknown; idpAmr?: unknown };
		if (!isAuthMethod(method) || typeof at !== "number" || !Number.isFinite(at)) continue;
		const seen = latest.get(method);
		if (seen !== undefined && at <= seen.at) continue;
		const amr = method === "federated" ? sanitizeIdpAmr(idpAmr) : [];
		latest.set(method, { method, at, ...(amr.length > 0 && { idpAmr: amr }) });
	}
	return [...latest.values()].sort((a, b) => b.at - a.at).slice(0, MAX_EVENTS);
}

/** Record that `method` was just proven. Replaces an older event of the same method. */
export function recordAuthEvent(
	events: AuthEvent[],
	method: AuthMethod,
	at: number,
	idpAmr?: readonly string[],
): AuthEvent[] {
	return normalizeEvents([...events, { method, at, ...(idpAmr && { idpAmr: [...idpAmr] }) }]);
}

function achievedRank(events: AuthEvent[]): number {
	if (events.length === 0) return 0;
	let rank = 1;
	const factors = new Set<Factor>();
	for (const event of events) {
		const traits = TRAITS[event.method];
		factors.add(traits.factor);
		if (traits.multi) rank = Math.max(rank, 3);
	}
	// Two different factor categories (password plus a code) make multi factor.
	if (factors.size >= 2) rank = Math.max(rank, 2);
	return rank;
}

/** Derive `amr`, `acr` and `authTime` from stored events. `sessionStart` (epoch seconds) is the fallback `authTime`. */
export function resolveAuthContext(events: AuthEvent[], sessionStart: number): AuthContext {
	const clean = normalizeEvents(events);
	const amr = new Set<string>();
	for (const event of clean) {
		for (const value of TRAITS[event.method].amr) amr.add(value);
		for (const value of event.idpAmr ?? []) amr.add(value);
	}
	const rank = achievedRank(clean);
	if (rank >= 2) amr.add("mfa");
	const first = clean[0];
	return {
		amr: [...amr].sort(),
		acr: ACR_ORDER[rank] ?? ACR.none,
		authTime: first ? first.at : sessionStart,
		events: clean,
	};
}

/** What a protected action demands of the person behind it. */
export interface AuthRequirement {
	/** Acceptable classes, as in the `acr_values` parameter. The context passes when it reaches the weakest one listed. Unknown values never pass. */
	acr?: string | readonly string[];
	/** The proving event must be at most this many seconds old (the `max_age` parameter). 0 always asks again. */
	maxAge?: number;
}

/** What a caller presents: `acr` and `auth_time` as carried by a session or an access token, plus `amr` when known. */
export interface AuthAssertion {
	acr?: string;
	/** Epoch seconds. */
	authTime?: number;
	amr?: readonly string[];
	/** Raw events. When present, `maxAge` is checked against the event that proves the class, not just the newest one. */
	events?: readonly AuthEvent[];
}

export type AuthRequirementResult =
	| { ok: true }
	| { ok: false; reason: "acr" | "max_age"; acr?: string[]; maxAge?: number };

/** The list form of a requirement's `acr`, split on spaces. Empty strings are dropped. */
export function acrList(acr: AuthRequirement["acr"]): string[] {
	if (acr === undefined) return [];
	const items = typeof acr === "string" ? acr.split(" ") : [...acr];
	return items.map((s) => s.trim()).filter((s) => s.length > 0);
}

function rankOf(acr: string): number {
	return (ACR_ORDER as readonly string[]).indexOf(acr);
}

/** The lowest rank the requirement accepts, or -1 when a listed value is not a known class (fail closed). */
function requiredRank(list: string[]): number {
	let min = Number.POSITIVE_INFINITY;
	for (const value of list) {
		const rank = rankOf(value);
		if (rank >= 0) min = Math.min(min, rank);
	}
	return Number.isFinite(min) ? min : -1;
}

/**
 * Decide whether an assertion meets a requirement (RFC 9470 section 4, OpenID Connect Core `max_age`).
 *
 * With `maxAge`, freshness is judged per class. A password typed a minute ago must not make an old
 * passkey look fresh, so when events are available the class needs a recent event whose method can
 * vouch for it: any fresh event for a single factor, a fresh code or passkey for multi factor, a fresh
 * passkey for phishing resistant. Without events (an access token) `auth_time` is the only evidence.
 */
export function evaluateAuthRequirement(
	assertion: AuthAssertion | null | undefined,
	requirement: AuthRequirement,
	nowSeconds: number,
): AuthRequirementResult {
	const wanted = acrList(requirement.acr);
	let neededRank = 0;
	if (wanted.length > 0) {
		// A client that must authenticate again should hear the whole requirement at once (RFC 9470 section 3: both parameters may occur together).
		const unmet: AuthRequirementResult = {
			ok: false,
			reason: "acr",
			acr: wanted,
			...(requirement.maxAge !== undefined && { maxAge: requirement.maxAge }),
		};
		neededRank = requiredRank(wanted);
		if (neededRank < 0) return unmet;
		if (!assertion?.acr || rankOf(assertion.acr) < neededRank) return unmet;
	}
	const { maxAge } = requirement;
	if (maxAge === undefined) return { ok: true };
	const stale: AuthRequirementResult = {
		ok: false,
		reason: "max_age",
		maxAge,
		...(wanted.length > 0 && { acr: wanted }),
	};
	if (!Number.isFinite(maxAge) || maxAge < 0) return stale;
	const oldest = nowSeconds - maxAge;
	const events = assertion?.events;
	if (events && events.length > 0) {
		// maxAge 0 means "authenticate again for this request": nothing recorded in the past qualifies.
		const fresh = events.some(
			(e) =>
				TRAITS[e.method].tier >= neededRank && e.at >= oldest && (maxAge > 0 || e.at >= nowSeconds),
		);
		return fresh ? { ok: true } : stale;
	}
	const authTime = assertion?.authTime;
	if (authTime === undefined || !Number.isFinite(authTime)) return stale;
	if (authTime < oldest || (maxAge === 0 && authTime < nowSeconds)) return stale;
	return { ok: true };
}

/**
 * Challenge for a resource that needs a stronger or fresher authentication (RFC 9470 section 3).
 * Built from a failed {@link evaluateAuthRequirement}. Sent with status 401.
 */
export function buildStepUpChallenge(
	scheme: "Bearer" | "DPoP",
	failure: Exclude<AuthRequirementResult, { ok: true }>,
	extra: { resourceMetadata?: string; description?: string } = {},
): string {
	const parts = [`error="insufficient_user_authentication"`];
	const description =
		extra.description ??
		(failure.reason === "max_age"
			? "A more recent authentication is required"
			: "A stronger authentication is required");
	parts.push(`error_description="${description.replace(/["\\\r\n]/g, " ")}"`);
	if (failure.acr && failure.acr.length > 0) {
		parts.push(`acr_values="${failure.acr.join(" ").replace(/["\\\r\n]/g, "")}"`);
	}
	if (failure.maxAge !== undefined && Number.isFinite(failure.maxAge)) {
		parts.push(`max_age="${Math.max(0, Math.floor(failure.maxAge))}"`);
	}
	if (extra.resourceMetadata) {
		parts.push(`resource_metadata="${extra.resourceMetadata.replace(/["\\\r\n]/g, "")}"`);
	}
	return `${scheme} ${parts.join(", ")}`;
}

/** Thrown when an action needs a stronger or fresher authentication than the caller has. */
export class StepUpRequiredError extends Error {
	readonly code = "STEP_UP_REQUIRED";
	constructor(
		readonly failure: Exclude<AuthRequirementResult, { ok: true }>,
		message = "Step-up authentication required",
	) {
		super(message);
		this.name = "StepUpRequiredError";
	}
}
