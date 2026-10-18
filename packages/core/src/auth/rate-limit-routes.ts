/**
 * Route table for the rateLimit() plugin: which shipped endpoint maps to which limit key,
 * plus the path normalization applied before matching and keying.
 */

export interface EndpointLimit {
	/** Duration string: "15m", "1h", "30s", "1d" */
	window: string;
	max: number;
}

export type EndpointKey =
	| "signIn"
	| "signUp"
	| "passwordReset"
	| "codeSend"
	| "codeVerify"
	| "agentAuthorize"
	| "mcpToken"
	| "mcpRegister"
	| "deviceCode"
	| "deviceToken"
	| "deviceAuthorize";

/**
 * Path suffix to limit key. Suffixes start with "/" so a match always lands on a segment
 * boundary, whatever mount prefix (basePath) the host uses. Paths are compared after
 * `normalizeRatePath`, so every entry is lowercase with no trailing slash.
 */
export const PATH_TO_CONFIG_KEY: ReadonlyArray<readonly [string, EndpointKey]> = [
	// Password and credential sign-in, plus second factor steps that finish a sign-in.
	["/auth/username/sign-in", "signIn"],
	["/auth/sign-in", "signIn"],
	["/auth/sign-in/two-factor", "signIn"],
	["/auth/sign-in/password-change", "signIn"],
	["/auth/username/change-password", "signIn"],
	["/auth/passkey/authenticate/verify", "signIn"],
	["/auth/passkey/login/verify", "signIn"],
	["/auth/siwe/verify", "signIn"],
	["/auth/one-tap/callback", "signIn"],
	// Account creation.
	["/auth/username/sign-up", "signUp"],
	["/auth/sign-up", "signUp"],
	["/auth/anonymous", "signUp"],
	["/auth/anonymous/upgrade", "signUp"],
	// Password reset (link and OTP variants).
	["/auth/forgot-password", "passwordReset"],
	["/auth/forgot-password/otp", "passwordReset"],
	["/auth/reset-password", "passwordReset"],
	["/auth/reset-password/otp", "passwordReset"],
	["/auth/password-reset", "passwordReset"],
	// Endpoints that send a code or link to an inbox or phone (message bombing).
	["/auth/magic-link/send", "codeSend"],
	["/auth/email-otp/send", "codeSend"],
	["/auth/otp/send", "codeSend"],
	["/auth/code/send", "codeSend"],
	["/auth/phone/send-code", "codeSend"],
	["/auth/2fa/otp/send", "codeSend"],
	["/auth/verify-email/send", "codeSend"],
	// Endpoints that accept a short code or one time token (guessing).
	["/auth/magic-link/verify", "codeVerify"],
	["/auth/email-otp/verify", "codeVerify"],
	["/auth/otp/verify", "codeVerify"],
	["/auth/code/verify", "codeVerify"],
	["/auth/phone/verify", "codeVerify"],
	["/auth/2fa/verify", "codeVerify"],
	["/auth/2fa/otp/verify", "codeVerify"],
	["/auth/2fa/enable", "codeVerify"],
	["/auth/2fa/disable", "codeVerify"],
	["/auth/2fa/backup-codes", "codeVerify"],
	["/auth/verify-email/confirm", "codeVerify"],
	["/auth/oauth/mobile/exchange", "codeVerify"],
	// Agent and device flows.
	["/auth/agent/authorize", "agentAuthorize"],
	["/auth/device/code", "deviceCode"],
	["/auth/device/token", "deviceToken"],
	["/auth/device/authorize", "deviceAuthorize"],
	["/mcp/token", "mcpToken"],
	["/mcp/register", "mcpRegister"],
];

/** Applied when the caller does not configure the endpoint. */
export const BUILT_IN_LIMITS: Readonly<Record<EndpointKey, EndpointLimit | undefined>> = {
	signIn: { window: "15m", max: 30 },
	signUp: { window: "1h", max: 10 },
	passwordReset: { window: "1h", max: 5 },
	codeSend: { window: "15m", max: 10 },
	codeVerify: { window: "15m", max: 30 },
	agentAuthorize: undefined,
	mcpToken: { window: "1m", max: 60 },
	mcpRegister: { window: "1h", max: 10 },
	deviceCode: { window: "1m", max: 10 },
	deviceToken: { window: "1m", max: 60 },
	deviceAuthorize: { window: "1m", max: 20 },
};

function decodeSegment(segment: string): string {
	try {
		return decodeURIComponent(segment);
	} catch {
		// Malformed escapes stay as they are; they still collapse and lowercase below.
		return segment;
	}
}

/**
 * Canonical form of a request path for limit lookup and counter keys. Every spelling a
 * router could serve as the same endpoint maps to one string: percent escapes are decoded
 * (so `%2F` becomes a separator), repeated slashes collapse, the trailing slash goes, and
 * the result is lowercased.
 */
export function normalizeRatePath(pathname: string): string {
	// Decode twice at most so `%252F` style double encoding cannot mint a fresh key.
	let decoded = pathname;
	for (let i = 0; i < 2; i++) {
		const next = decoded.split("/").map(decodeSegment).join("/");
		if (next === decoded) break;
		decoded = next;
	}
	const collapsed = decoded.replace(/\/{2,}/g, "/").replace(/\\+/g, "/");
	const trimmed = collapsed.length > 1 ? collapsed.replace(/\/+$/, "") : collapsed;
	return (trimmed.startsWith("/") ? trimmed : `/${trimmed}`).toLowerCase();
}

/** The limit key for a normalized path, or null when no specific limit applies. */
export function endpointKeyFor(normalizedPath: string): EndpointKey | null {
	let best: { length: number; key: EndpointKey } | null = null;
	for (const [suffix, key] of PATH_TO_CONFIG_KEY) {
		if (normalizedPath === suffix || normalizedPath.endsWith(suffix)) {
			if (!best || suffix.length > best.length) best = { length: suffix.length, key };
		}
	}
	return best ? best.key : null;
}
