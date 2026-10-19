/**
 * HTTP routes of the email and password module. They are plugin endpoints, so
 * `createTheAuthHandler` serves them next to `GET /auth/session` and `POST /auth/sign-out`
 * with no extra wiring.
 *
 * | Route | Body | Answer |
 * | --- | --- | --- |
 * | `POST /auth/email/sign-up` | `{ email, password, name? }` | 201 `{ verificationRequired: true }`, or `{ user, session }` when verification is off |
 * | `POST /auth/email/sign-in` | `{ email, password, rememberMe? }` | 200 `{ user, session }` and the session cookie |
 * | `POST /auth/email/verify` | `{ token }` | 200 `{ verified: true, user }` |
 * | `POST /auth/email/resend-verification` | `{ email }` | 204, whether or not the address exists |
 * | `POST /auth/email/forgot-password` | `{ email }` | 204 (needs `passwordReset`) |
 * | `POST /auth/email/reset-password` | `{ token, password }` | 200 `{ success: true }` (needs `passwordReset`) |
 * | `POST /auth/email/change-password` | `{ current, newPassword }` | 200 `{ success: true }`, signed-in user only |
 *
 * Errors are `{ error: { code, message } }`.
 */

import { buildSessionSetCookie, json, parseBody, parseRememberMe } from "../plugin/helpers.js";
import type { PluginRegistry } from "../plugin/runner.js";
import type { EndpointContext, PluginEndpoint } from "../plugin/types.js";
import { UserBannedError } from "../session/banned.js";
import type { SessionManager } from "../session/session.js";
import type { EmailPasswordModule } from "./email-password.js";
import { EmailPasswordError } from "./email-password.js";
import { LoginLockedError } from "./login-lockout.js";
import type { PasswordResetModule } from "./password-reset.js";
import { SignInGateError, signInGateResponse } from "./sign-in-gate.js";

export interface EmailPasswordHttpDeps {
	passwordReset: PasswordResetModule | null;
	sessionManager: SessionManager | null;
	/** `config.baseUrl`: an https URL turns on the `Secure` cookie attribute. */
	baseUrl?: string;
}

const STATUS: Record<EmailPasswordError["code"], number> = {
	INVALID_EMAIL: 400,
	INVALID_PASSWORD: 400,
	INVALID_TOKEN: 400,
	EMAIL_TAKEN: 409,
	INVALID_CREDENTIALS: 401,
	EMAIL_NOT_VERIFIED: 403,
};

function fail(code: string, message: string, status: number, headers?: HeadersInit): Response {
	return new Response(JSON.stringify({ error: { code, message } }), {
		status,
		headers: { "Content-Type": "application/json", ...headers },
	});
}

function errorResponse(err: unknown): Response {
	if (err instanceof EmailPasswordError) return fail(err.code, err.message, STATUS[err.code]);
	if (err instanceof SignInGateError) return signInGateResponse(err);
	if (err instanceof UserBannedError) return fail(err.code, err.message, 403);
	if (err instanceof LoginLockedError) {
		return new Response(
			JSON.stringify({
				error: { code: "SIGN_IN_LOCKED", message: err.message },
				retryAfter: err.retryAfterSeconds,
			}),
			{
				status: 429,
				headers: {
					"Content-Type": "application/json",
					"Retry-After": String(err.retryAfterSeconds),
				},
			},
		);
	}
	return fail("INTERNAL_ERROR", "Something went wrong", 500);
}

const str = (v: unknown): string => (typeof v === "string" ? v : "");

function isJson(request: Request): boolean {
	return (request.headers.get("content-type") ?? "").toLowerCase().includes("application/json");
}

/** Registers the routes on the plugin endpoint list. */
export function registerEmailPasswordEndpoints(
	registry: Pick<PluginRegistry, "endpoints">,
	module: EmailPasswordModule | null,
	deps: EmailPasswordHttpDeps,
): void {
	const { passwordReset, sessionManager } = deps;
	if (!module || !sessionManager) return;
	const cookieName = sessionManager.cookieName ?? "theauth_session";
	const secureCookie = (deps.baseUrl ?? "").startsWith("https://");

	function sessionResponse(
		status: number,
		body: Record<string, unknown>,
		session: { token: string; expiresAt: Date; rememberMe?: boolean },
	): Response {
		return new Response(JSON.stringify({ ...body, session }), {
			status,
			headers: {
				"Content-Type": "application/json",
				"Set-Cookie": buildSessionSetCookie(cookieName, session.token, session, secureCookie),
			},
		});
	}

	/** Wraps a handler with body parsing and error mapping. */
	function post(
		path: string,
		description: string,
		run: (b: Record<string, unknown>, request: Request, ctx: EndpointContext) => Promise<Response>,
		extra: Pick<NonNullable<PluginEndpoint["metadata"]>, "rateLimit" | "requireAuth"> = {},
	): void {
		registry.endpoints.push({
			method: "POST",
			path,
			metadata: { description, ...extra },
			async handler(request, ctx) {
				const parsed = await parseBody(request);
				if (!parsed.ok) return fail("INVALID_BODY", "Invalid JSON body", 400);
				try {
					return await run(parsed.data, request, ctx);
				} catch (err) {
					return errorResponse(err);
				}
			},
		});
	}

	post(
		"/auth/email/sign-up",
		"Create an account with an email and password",
		async (b) => {
			const result = await module.signUp({
				email: str(b.email),
				password: str(b.password),
				...(typeof b.name === "string" && { name: b.name }),
			});
			if (result.verificationRequired) return json({ verificationRequired: true }, 201);
			return sessionResponse(201, { user: result.user }, result.session);
		},
		{ rateLimit: { window: 60, max: 5 } },
	);

	post(
		"/auth/email/sign-in",
		"Sign in with an email and password",
		async (b, request) => {
			const rememberMe = parseRememberMe(b.rememberMe);
			const result = await module.signIn(
				{
					email: str(b.email),
					password: str(b.password),
					...(rememberMe !== undefined && { rememberMe }),
				},
				{ request },
			);
			return sessionResponse(200, { user: result.user }, result.session);
		},
		{ rateLimit: { window: 60, max: 10 } },
	);

	post("/auth/email/verify", "Verify an email address with the emailed token", async (b) => {
		const user = await module.verifyEmail(str(b.token));
		return json({ verified: true, user });
	});

	post(
		"/auth/email/resend-verification",
		"Send the verification email again",
		async (b) => {
			await module.resendVerification(str(b.email));
			return new Response(null, { status: 204 });
		},
		{ rateLimit: { window: 60, max: 3 } },
	);

	if (passwordReset) {
		post(
			"/auth/email/forgot-password",
			"Email a password reset link",
			async (b) => {
				await passwordReset.requestReset(str(b.email));
				return new Response(null, { status: 204 });
			},
			{ rateLimit: { window: 60, max: 3 } },
		);

		post("/auth/email/reset-password", "Set a new password with the emailed token", async (b) => {
			const result = await passwordReset.resetPassword(str(b.token), str(b.password));
			if (!result.success) {
				const code =
					result.error.code === "INVALID_PASSWORD" ? "INVALID_PASSWORD" : "INVALID_TOKEN";
				return fail(code, result.error.message, 400);
			}
			// A reset link proves the owner reads this inbox, so the address counts as verified.
			await module.markVerified(result.data.userId);
			return json({ success: true });
		});
	}

	post(
		"/auth/email/change-password",
		"Change the password of the signed-in user",
		async (b, request, ctx) => {
			const user = await ctx.getUser(request);
			if (!user) return fail("UNAUTHORIZED", "Authentication required", 401);
			// A JSON content type forces a CORS preflight, so a cross-site form cannot ride the cookie.
			if (!isJson(request)) {
				return fail("UNSUPPORTED_MEDIA_TYPE", "Content-Type must be application/json", 415);
			}
			try {
				await module.changePassword(user.id, str(b.current), str(b.newPassword), { request });
			} catch (err) {
				if (err instanceof EmailPasswordError && err.code === "INVALID_CREDENTIALS") {
					return fail(err.code, err.message, 400);
				}
				throw err;
			}
			return json({ success: true });
		},
		{ requireAuth: true },
	);
}
