/**
 * Captcha integration for TheAuth.
 *
 * Supports reCAPTCHA v2/v3, hCaptcha, and Cloudflare Turnstile. All three
 * providers share the same verification pattern: POST form-encoded data with
 * `secret` and `response` (the client token) to a provider-specific endpoint.
 *
 * @example
 * ```typescript
 * const kavach = await createKavach({
 *   database: { provider: 'sqlite', url: 'kavach.db' },
 *   captcha: {
 *     provider: 'turnstile',
 *     secretKey: process.env.TURNSTILE_SECRET,
 *   },
 * });
 *
 * // In a route handler
 * const captchaToken = request.headers.get('X-Captcha-Token') ?? '';
 * const result = await kavach.captcha?.verify(captchaToken);
 * if (!result?.success) return new Response('Captcha failed', { status: 403 });
 * ```
 */

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface CaptchaConfig {
	/** Captcha provider */
	provider: "recaptcha" | "hcaptcha" | "turnstile";
	/** Secret key from the provider dashboard */
	secretKey: string;
	/**
	 * Auth endpoint names that require captcha verification.
	 * Default: ['sign-up', 'sign-in', 'reset-password']
	 */
	protectedEndpoints?: string[];
	/**
	 * Minimum score for reCAPTCHA v3 (0.0 to 1.0).
	 * Requests scoring below this are rejected. Default: 0.5
	 */
	minScore?: number;
}

export interface CaptchaVerifyResult {
	success: boolean;
	score?: number;
	error?: string;
}

export interface CaptchaModule {
	/** Verify a client-side captcha token. */
	verify: (token: string, ip?: string) => Promise<CaptchaVerifyResult>;
	/**
	 * Check the captcha token from the request's `X-Captcha-Token` header.
	 * Returns `{ valid: false }` when the header is missing or verification fails.
	 */
	middleware: (request: Request) => Promise<{ valid: boolean; error?: string }>;
}

// ---------------------------------------------------------------------------
// Provider endpoints
// ---------------------------------------------------------------------------

const PROVIDER_URLS: Record<CaptchaConfig["provider"], string> = {
	recaptcha: "https://www.google.com/recaptcha/api/siteverify",
	hcaptcha: "https://hcaptcha.com/siteverify",
	turnstile: "https://challenges.cloudflare.com/turnstile/v0/siteverify",
};

// ---------------------------------------------------------------------------
// Types for provider responses
// ---------------------------------------------------------------------------

interface RecaptchaResponse {
	success: boolean;
	score?: number;
	action?: string;
	challenge_ts?: string;
	hostname?: string;
	"error-codes"?: string[];
}

interface HcaptchaResponse {
	success: boolean;
	score?: number;
	"error-codes"?: string[];
}

interface TurnstileResponse {
	success: boolean;
	"error-codes"?: string[];
}

type ProviderResponse = RecaptchaResponse | HcaptchaResponse | TurnstileResponse;

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

// const DEFAULT_PROTECTED_ENDPOINTS = ["sign-up", "sign-in", "reset-password"];
const DEFAULT_MIN_SCORE = 0.5;

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

export function createCaptchaModule(config: CaptchaConfig): CaptchaModule {
	const verifyUrl = PROVIDER_URLS[config.provider];
	const minScore = config.minScore ?? DEFAULT_MIN_SCORE;

	async function verify(token: string, ip?: string): Promise<CaptchaVerifyResult> {
		if (!token) {
			return { success: false, error: "Missing captcha token" };
		}

		const params = new URLSearchParams({
			secret: config.secretKey,
			response: token,
		});

		if (ip) {
			params.set("remoteip", ip);
		}

		let data: ProviderResponse;
		try {
			const response = await fetch(verifyUrl, {
				method: "POST",
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body: params.toString(),
			});

			if (!response.ok) {
				return {
					success: false,
					error: `Provider returned HTTP ${response.status}`,
				};
			}

			data = (await response.json()) as ProviderResponse;
		} catch (err) {
			return {
				success: false,
				error: err instanceof Error ? err.message : "Network error",
			};
		}

		if (!data.success) {
			const codes =
				"error-codes" in data && Array.isArray(data["error-codes"])
					? (data["error-codes"] as string[]).join(", ")
					: "unknown";
			return { success: false, error: `Captcha failed: ${codes}` };
		}

		// reCAPTCHA v3 score check
		if (config.provider === "recaptcha" && "score" in data && data.score !== undefined) {
			const score = data.score;
			if (score < minScore) {
				return {
					success: false,
					score,
					error: `Score ${score} below minimum ${minScore}`,
				};
			}
			return { success: true, score };
		}

		// hCaptcha may return a score
		if (config.provider === "hcaptcha" && "score" in data && data.score !== undefined) {
			return { success: true, score: data.score };
		}

		return { success: true };
	}

	async function middleware(request: Request): Promise<{ valid: boolean; error?: string }> {
		const token = request.headers.get("X-Captcha-Token");
		if (!token) {
			return { valid: false, error: "Missing X-Captcha-Token header" };
		}

		const ip =
			request.headers.get("CF-Connecting-IP") ??
			request.headers.get("X-Forwarded-For")?.split(",")[0]?.trim() ??
			undefined;

		const result = await verify(token, ip);
		return result.success ? { valid: true } : { valid: false, error: result.error };
	}

	return { verify, middleware };
}
