/**
 * HTTP surface of the username module (`theauth.username.handleRequest`).
 *
 * Sign-up and sign-in are public. Change-username and change-password act on the account
 * of the signed-in session only: the user id comes from the validated session token, a
 * `userId` in the body is ignored, and with no session the answer is 401.
 */

import { extractToken, parseRememberMe } from "../plugin/helpers.js";
import type { SessionManager } from "../session/session.js";
import { LoginLockedError } from "./login-lockout.js";
import { SignInGateError, signInGateResponse } from "./sign-in-gate.js";
import type { UsernameAuthModule } from "./username.js";

type UsernameOps = Pick<
	UsernameAuthModule,
	"signUp" | "signIn" | "changePassword" | "changeUsername"
>;

const HANDLED_PATHS = new Set([
	"/auth/username/sign-up",
	"/auth/username/sign-in",
	"/auth/username/change-password",
	"/auth/username/change-username",
]);

/** The one error change-password gives for an unknown account and a wrong password alike. */
export const CHANGE_PASSWORD_REFUSED = "Current password is incorrect";

function jsonResponse(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json" },
	});
}

function lockedResponse(err: LoginLockedError): Response {
	return new Response(
		JSON.stringify({
			error: err.message,
			code: "SIGN_IN_LOCKED",
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

function isJsonRequest(request: Request): boolean {
	return (request.headers.get("content-type") ?? "").toLowerCase().includes("application/json");
}

export function createUsernameRequestHandler(
	ops: UsernameOps,
	sessionManager: SessionManager,
): (request: Request) => Promise<Response | null> {
	/** The signed-in user id from a Bearer token or the session cookie, or null. */
	async function sessionUserId(request: Request): Promise<string | null> {
		const token = extractToken(request, sessionManager.cookieName);
		if (!token) return null;
		try {
			const session = await sessionManager.validate(token);
			return session?.userId ?? null;
		} catch {
			return null;
		}
	}

	async function signUpRoute(b: Record<string, unknown>): Promise<Response> {
		if (typeof b.username !== "string" || typeof b.password !== "string") {
			return jsonResponse({ error: "Missing required fields: username, password" }, 400);
		}
		try {
			const result = await ops.signUp({
				username: b.username,
				password: b.password,
				name: typeof b.name === "string" ? b.name : undefined,
			});
			return jsonResponse(result, 201);
		} catch (err) {
			return jsonResponse({ error: err instanceof Error ? err.message : "Sign-up failed" }, 400);
		}
	}

	async function signInRoute(request: Request, b: Record<string, unknown>): Promise<Response> {
		if (typeof b.username !== "string" || typeof b.password !== "string") {
			return jsonResponse({ error: "Missing required fields: username, password" }, 400);
		}
		try {
			const rememberMe = parseRememberMe(b.rememberMe);
			const result = await ops.signIn(
				{
					username: b.username,
					password: b.password,
					...(rememberMe !== undefined && { rememberMe }),
				},
				{ request },
			);
			return jsonResponse(result);
		} catch (err) {
			if (err instanceof SignInGateError) return signInGateResponse(err);
			if (err instanceof LoginLockedError) return lockedResponse(err);
			return jsonResponse({ error: "Invalid username or password" }, 401);
		}
	}

	async function changePasswordRoute(
		request: Request,
		userId: string,
		b: Record<string, unknown>,
	): Promise<Response> {
		if (typeof b.current !== "string" || typeof b.newPassword !== "string") {
			return jsonResponse({ error: "Missing required fields: current, newPassword" }, 400);
		}
		try {
			return jsonResponse(await ops.changePassword(userId, b.current, b.newPassword, { request }));
		} catch (err) {
			if (err instanceof LoginLockedError) return lockedResponse(err);
			// Only the generic refusal or a new-password policy message reaches the caller.
			return jsonResponse(
				{ error: err instanceof Error ? err.message : CHANGE_PASSWORD_REFUSED },
				400,
			);
		}
	}

	async function changeUsernameRoute(userId: string, b: Record<string, unknown>) {
		if (typeof b.newUsername !== "string") {
			return jsonResponse({ error: "Missing required field: newUsername" }, 400);
		}
		try {
			return jsonResponse(await ops.changeUsername(userId, b.newUsername));
		} catch (err) {
			return jsonResponse(
				{ error: err instanceof Error ? err.message : "Change username failed" },
				400,
			);
		}
	}

	return async function handleRequest(request: Request): Promise<Response | null> {
		if (request.method !== "POST") return null;
		const { pathname } = new URL(request.url);
		if (!HANDLED_PATHS.has(pathname)) return null;

		const accountChange =
			pathname === "/auth/username/change-password" ||
			pathname === "/auth/username/change-username";
		let userId: string | null = null;
		if (accountChange) {
			userId = await sessionUserId(request);
			if (!userId) return jsonResponse({ error: "Authentication required" }, 401);
			// A JSON content type forces a CORS preflight, so a cross-site form cannot ride
			// the session cookie into an account change.
			if (!isJsonRequest(request)) {
				return jsonResponse({ error: "Content-Type must be application/json" }, 415);
			}
		}

		let body: unknown;
		try {
			body = await request.json();
		} catch {
			return jsonResponse({ error: "Invalid JSON body" }, 400);
		}
		const b = (body ?? {}) as Record<string, unknown>;

		if (pathname === "/auth/username/sign-up") return signUpRoute(b);
		if (pathname === "/auth/username/sign-in") return signInRoute(request, b);
		if (!userId) return jsonResponse({ error: "Authentication required" }, 401);
		if (pathname === "/auth/username/change-password") {
			return changePasswordRoute(request, userId, b);
		}
		return changeUsernameRoute(userId, b);
	};
}
