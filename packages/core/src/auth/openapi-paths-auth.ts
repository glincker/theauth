import { BEARER_SECURITY, errorResponses, jsonBody, jsonOk, pathParam } from "./openapi-helpers.js";
import type { OpenApiPathItem, OpenApiSchema } from "./openapi-types.js";

export function agentsPaths(base: string): Record<string, OpenApiPathItem> {
	const agentSchema: OpenApiSchema = {
		type: "object",
		properties: {
			id: { type: "string" },
			ownerId: { type: "string" },
			tenantId: { type: "string", nullable: true },
			name: { type: "string" },
			type: { type: "string", enum: ["autonomous", "delegated", "service"] },
			token: { type: "string" },
			status: { type: "string", enum: ["active", "revoked", "expired"] },
			expiresAt: { type: "string", format: "date-time", nullable: true },
			createdAt: { type: "string", format: "date-time" },
			updatedAt: { type: "string", format: "date-time" },
		},
		required: ["id", "ownerId", "name", "type", "token", "status", "createdAt", "updatedAt"],
	};

	const createAgentBody: OpenApiSchema = {
		type: "object",
		properties: {
			ownerId: { type: "string" },
			name: { type: "string" },
			type: { type: "string", enum: ["autonomous", "delegated", "service"] },
			permissions: {
				type: "array",
				items: {
					type: "object",
					properties: {
						resource: { type: "string" },
						actions: { type: "array", items: { type: "string" } },
					},
					required: ["resource", "actions"],
				},
			},
			expiresAt: { type: "string", format: "date-time" },
		},
		required: ["ownerId", "name", "type", "permissions"],
	};

	return {
		[`${base}/agents`]: {
			post: {
				operationId: "createAgent",
				summary: "Create a new agent identity",
				tags: ["Agents"],
				security: BEARER_SECURITY,
				requestBody: jsonBody(createAgentBody),
				responses: {
					...jsonOk(agentSchema),
					...errorResponses(true, false),
				},
			},
			get: {
				operationId: "listAgents",
				summary: "List agent identities",
				tags: ["Agents"],
				security: BEARER_SECURITY,
				responses: {
					...jsonOk({ type: "array", items: agentSchema }),
					...errorResponses(true, false),
				},
			},
		},
		[`${base}/agents/{id}`]: {
			get: {
				operationId: "getAgent",
				summary: "Get an agent by ID",
				tags: ["Agents"],
				security: BEARER_SECURITY,
				parameters: [pathParam("id", "Agent ID")],
				responses: {
					...jsonOk(agentSchema),
					...errorResponses(true, true),
				},
			},
			delete: {
				operationId: "deleteAgent",
				summary: "Delete (revoke) an agent",
				tags: ["Agents"],
				security: BEARER_SECURITY,
				parameters: [pathParam("id", "Agent ID")],
				responses: {
					"204": { description: "Agent deleted" },
					...errorResponses(true, true),
				},
			},
		},
		[`${base}/agents/{id}/rotate`]: {
			post: {
				operationId: "rotateAgent",
				summary: "Rotate an agent token",
				tags: ["Agents"],
				security: BEARER_SECURITY,
				parameters: [pathParam("id", "Agent ID")],
				responses: {
					...jsonOk(agentSchema),
					...errorResponses(true, true),
				},
			},
		},
	};
}

export function authPaths(base: string): Record<string, OpenApiPathItem> {
	const sessionSchema: OpenApiSchema = {
		type: "object",
		properties: {
			id: { type: "string" },
			userId: { type: "string" },
			token: { type: "string" },
			expiresAt: { type: "string", format: "date-time" },
			createdAt: { type: "string", format: "date-time" },
		},
		required: ["id", "userId", "token", "expiresAt", "createdAt"],
	};

	const userSchema: OpenApiSchema = {
		type: "object",
		properties: {
			id: { type: "string" },
			email: { type: "string", format: "email" },
			name: { type: "string", nullable: true },
			createdAt: { type: "string", format: "date-time" },
		},
		required: ["id", "email", "createdAt"],
	};

	const emailPasswordBody: OpenApiSchema = {
		type: "object",
		properties: {
			email: { type: "string", format: "email" },
			password: { type: "string", format: "password" },
		},
		required: ["email", "password"],
	};

	const signInOkSchema: OpenApiSchema = {
		type: "object",
		properties: {
			success: { type: "boolean", example: true },
			data: {
				type: "object",
				properties: {
					user: userSchema,
					session: sessionSchema,
				},
				required: ["user", "session"],
			},
		},
		required: ["success", "data"],
	};

	return {
		[`${base}/sign-in/email`]: {
			post: {
				operationId: "signInEmail",
				summary: "Sign in with email and password",
				tags: ["Auth"],
				requestBody: jsonBody(emailPasswordBody),
				responses: {
					...jsonOk(signInOkSchema),
					...errorResponses(false, false),
				},
			},
		},
		[`${base}/sign-up/email`]: {
			post: {
				operationId: "signUpEmail",
				summary: "Create a new account with email and password",
				tags: ["Auth"],
				requestBody: jsonBody({
					type: "object",
					properties: {
						email: { type: "string", format: "email" },
						password: { type: "string", format: "password" },
						name: { type: "string" },
					},
					required: ["email", "password"],
				}),
				responses: {
					...jsonOk(signInOkSchema),
					...errorResponses(false, false),
				},
			},
		},
		[`${base}/sign-out`]: {
			post: {
				operationId: "signOut",
				summary: "Sign out and invalidate the current session",
				tags: ["Auth"],
				security: BEARER_SECURITY,
				responses: {
					"204": { description: "Signed out successfully" },
					...errorResponses(true, false),
				},
			},
		},
		[`${base}/session`]: {
			get: {
				operationId: "getSession",
				summary: "Get the current session and user",
				tags: ["Auth"],
				security: BEARER_SECURITY,
				responses: {
					...jsonOk(signInOkSchema),
					...errorResponses(true, false),
				},
			},
		},
		[`${base}/auth/magic-link/send`]: {
			post: {
				operationId: "sendMagicLink",
				summary: "Send a magic link to an email address",
				tags: ["Auth"],
				requestBody: jsonBody({
					type: "object",
					properties: { email: { type: "string", format: "email" } },
					required: ["email"],
				}),
				responses: {
					"204": { description: "Magic link sent" },
					...errorResponses(false, false),
				},
			},
		},
		[`${base}/auth/magic-link/verify`]: {
			post: {
				operationId: "verifyMagicLink",
				summary: "Verify a magic link token and create a session",
				tags: ["Auth"],
				requestBody: jsonBody({
					type: "object",
					properties: { token: { type: "string" } },
					required: ["token"],
				}),
				responses: {
					...jsonOk(signInOkSchema),
					...errorResponses(false, false),
				},
			},
		},
		[`${base}/auth/email-otp/send`]: {
			post: {
				operationId: "sendEmailOtp",
				summary: "Send a one-time passcode to an email address",
				tags: ["Auth"],
				requestBody: jsonBody({
					type: "object",
					properties: { email: { type: "string", format: "email" } },
					required: ["email"],
				}),
				responses: {
					"204": { description: "OTP sent" },
					...errorResponses(false, false),
				},
			},
		},
		[`${base}/auth/email-otp/verify`]: {
			post: {
				operationId: "verifyEmailOtp",
				summary: "Verify an email OTP and create a session",
				tags: ["Auth"],
				requestBody: jsonBody({
					type: "object",
					properties: {
						email: { type: "string", format: "email" },
						code: { type: "string" },
					},
					required: ["email", "code"],
				}),
				responses: {
					...jsonOk(signInOkSchema),
					...errorResponses(false, false),
				},
			},
		},
		[`${base}/auth/forgot-password`]: {
			post: {
				operationId: "forgotPassword",
				summary: "Request a password reset email",
				tags: ["Auth"],
				requestBody: jsonBody({
					type: "object",
					properties: { email: { type: "string", format: "email" } },
					required: ["email"],
				}),
				responses: {
					"204": { description: "Reset email sent" },
					...errorResponses(false, false),
				},
			},
		},
		[`${base}/auth/reset-password`]: {
			post: {
				operationId: "resetPassword",
				summary: "Reset a password using a token from email",
				tags: ["Auth"],
				requestBody: jsonBody({
					type: "object",
					properties: {
						token: { type: "string" },
						password: { type: "string", format: "password" },
					},
					required: ["token", "password"],
				}),
				responses: {
					"204": { description: "Password reset successfully" },
					...errorResponses(false, false),
				},
			},
		},
		[`${base}/auth/two-factor/verify`]: {
			post: {
				operationId: "verifyTwoFactor",
				summary: "Verify a TOTP code for two-factor authentication",
				tags: ["Auth"],
				security: BEARER_SECURITY,
				requestBody: jsonBody({
					type: "object",
					properties: { code: { type: "string", description: "6-digit TOTP code" } },
					required: ["code"],
				}),
				responses: {
					...jsonOk(signInOkSchema),
					...errorResponses(true, false),
				},
			},
		},
	};
}
export function oauthPaths(base: string): Record<string, OpenApiPathItem> {
	return {
		[`${base}/auth/{provider}`]: {
			get: {
				operationId: "oauthRedirect",
				summary: "Redirect to OAuth provider authorization page",
				tags: ["OAuth"],
				parameters: [pathParam("provider", "OAuth provider name (e.g. google, github, discord)")],
				responses: {
					"302": { description: "Redirect to provider" },
					...errorResponses(false, false),
				},
			},
		},
		[`${base}/auth/{provider}/callback`]: {
			get: {
				operationId: "oauthCallback",
				summary: "Handle OAuth provider callback and create session",
				tags: ["OAuth"],
				parameters: [
					pathParam("provider", "OAuth provider name"),
					{
						name: "code",
						in: "query",
						required: true,
						schema: { type: "string" },
						description: "Authorization code from provider",
					},
					{
						name: "state",
						in: "query",
						required: false,
						schema: { type: "string" },
						description: "CSRF state parameter",
					},
				],
				responses: {
					"302": { description: "Redirect after authentication" },
					...errorResponses(false, false),
				},
			},
		},
	};
}
