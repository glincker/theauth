/**
 * Routes that finish a gated sign-in and manage trusted devices.
 * `createTheAuth` registers this plugin automatically when `auth.session` is configured, unless a plugin with id `theauth-sign-in-gate` is already present.
 */

import { buildSetCookie, json, parseBody } from "../plugin/helpers.js";
import type { PluginContext, TheAuthPlugin } from "../plugin/types.js";
import type { Session } from "../session/session.js";
import type { SignInGate, SignInGateDecision, TrustedDeviceCookie } from "./sign-in-gate.js";
import { SignInGateError, signInGateResponse } from "./sign-in-gate.js";

const DEFAULT_SESSION_COOKIE = "theauth_session";

function str(value: unknown): string | null {
	return typeof value === "string" && value.length > 0 ? value : null;
}

export function signInGatePlugin(): TheAuthPlugin {
	return {
		id: "theauth-sign-in-gate",

		async init(ctx: PluginContext): Promise<undefined> {
			const gate = ctx.signInGate;
			const sessionManager = ctx.sessionManager;
			if (!gate || !sessionManager) return undefined;

			const secure = (ctx.config.baseUrl ?? "").startsWith("https://");
			const sessionCookie = ctx.config.auth?.session?.cookieName ?? DEFAULT_SESSION_COOKIE;

			async function issueSession(
				userId: string,
				extra: { twoFactor: boolean },
				deviceCookie?: TrustedDeviceCookie,
			): Promise<Response> {
				if (!sessionManager) return json({ error: "Sessions are not configured" }, 500);
				const metadata = extra.twoFactor ? { twoFactor: true } : undefined;
				let created: { session: Session; token: string };
				try {
					created = await sessionManager.create(userId, metadata);
				} catch (err) {
					const message = err instanceof Error ? err.message : "Failed to create session";
					return json({ error: message }, 429);
				}
				const maxAge = Math.max(
					0,
					Math.floor((created.session.expiresAt.getTime() - Date.now()) / 1000),
				);
				const headers = new Headers({ "Content-Type": "application/json" });
				headers.append(
					"Set-Cookie",
					buildSetCookie(sessionCookie, created.token, maxAge, "/", secure),
				);
				if (deviceCookie) {
					headers.append(
						"Set-Cookie",
						buildSetCookie(deviceCookie.name, deviceCookie.value, deviceCookie.maxAge, "/", secure),
					);
				}
				return new Response(
					JSON.stringify({
						user: { id: userId },
						session: { token: created.token, expiresAt: created.session.expiresAt },
					}),
					{ status: 200, headers },
				);
			}

			function decisionResponse(decision: Exclude<SignInGateDecision, { action: "allow" }>) {
				return signInGateResponse(new SignInGateError(decision));
			}

			ctx.addEndpoint({
				method: "POST",
				path: "/auth/sign-in/two-factor",
				metadata: {
					rateLimit: { window: 60, max: 10 },
					description: "Complete a sign-in with a two-factor code and a gate challenge",
				},
				async handler(request) {
					const body = await parseBody(request);
					if (!body.ok) return body.response;
					const challenge = str(body.data.challenge);
					const code = str(body.data.code);
					if (!challenge || !code) {
						return json({ error: "Missing required fields: challenge, code" }, 400);
					}
					const factor = str(body.data.factor);
					const result = await gate.completeTwoFactor({
						challenge,
						code,
						request,
						trustDevice: body.data.trustDevice === true,
						...(factor && { factor }),
					});
					if (!result.ok) {
						const status = result.reason === "too_many_attempts" ? 429 : 401;
						return json({ error: { code: result.reason.toUpperCase() } }, status);
					}
					return issueSession(result.userId, { twoFactor: true }, result.trustedDeviceCookie);
				},
			});

			ctx.addEndpoint({
				method: "POST",
				path: "/auth/sign-in/password-change",
				metadata: {
					rateLimit: { window: 60, max: 10 },
					description: "Complete a forced password change with a gate challenge",
				},
				async handler(request) {
					const body = await parseBody(request);
					if (!body.ok) return body.response;
					const challenge = str(body.data.challenge);
					const newPassword = str(body.data.newPassword);
					if (!challenge || !newPassword) {
						return json({ error: "Missing required fields: challenge, newPassword" }, 400);
					}
					const result = await gate.completePasswordChange({ challenge, newPassword, request });
					if (!result.ok) {
						const status = result.reason === "invalid_challenge" ? 401 : 400;
						return json(
							{ error: { code: result.reason.toUpperCase(), message: result.message } },
							status,
						);
					}
					if (result.next.action === "allow") {
						return issueSession(result.userId, { twoFactor: false });
					}
					return decisionResponse(result.next);
				},
			});

			registerTrustedDeviceRoutes(ctx, gate);
			return undefined;
		},
	};
}

function registerTrustedDeviceRoutes(ctx: PluginContext, gate: SignInGate): void {
	ctx.addEndpoint({
		method: "GET",
		path: "/auth/trusted-devices",
		metadata: { requireAuth: true, description: "List trusted devices for the signed-in user" },
		async handler(request, endpointCtx) {
			const user = await endpointCtx.getUser(request);
			if (!user) return json({ error: "Authentication required" }, 401);
			const devices = await gate.listTrustedDevices(user.id);
			return json({
				devices: devices.map((d) => ({
					id: d.id,
					label: d.label,
					trustedAt: d.trustedAt,
					expiresAt: d.expiresAt,
				})),
			});
		},
	});

	ctx.addEndpoint({
		method: "POST",
		path: "/auth/trusted-devices/revoke",
		metadata: { requireAuth: true, description: "Revoke one trusted device by id" },
		async handler(request, endpointCtx) {
			const user = await endpointCtx.getUser(request);
			if (!user) return json({ error: "Authentication required" }, 401);
			const body = await parseBody(request);
			if (!body.ok) return body.response;
			const id = str(body.data.id);
			if (!id) return json({ error: "Missing required field: id" }, 400);
			const revoked = await gate.revokeTrustedDevice(user.id, id);
			return revoked ? json({ revoked: true }) : json({ error: "Device not found" }, 404);
		},
	});

	ctx.addEndpoint({
		method: "POST",
		path: "/auth/trusted-devices/revoke-all",
		metadata: { requireAuth: true, description: "Revoke every trusted device" },
		async handler(request, endpointCtx) {
			const user = await endpointCtx.getUser(request);
			if (!user) return json({ error: "Authentication required" }, 401);
			await gate.revokeAllTrustedDevices(user.id);
			return json({ revoked: true });
		},
	});
}
