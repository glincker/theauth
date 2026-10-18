import { BEARER_SECURITY, errorResponses, jsonBody, jsonOk, pathParam } from "./openapi-helpers.js";
import type { OpenApiPathItem, OpenApiSchema } from "./openapi-types.js";

export function sessionsPaths(base: string): Record<string, OpenApiPathItem> {
	const sessionSchema: OpenApiSchema = {
		type: "object",
		properties: {
			id: { type: "string" },
			userId: { type: "string" },
			userAgent: { type: "string", nullable: true },
			ipAddress: { type: "string", nullable: true },
			expiresAt: { type: "string", format: "date-time" },
			createdAt: { type: "string", format: "date-time" },
			current: { type: "boolean", description: "True if this is the active session" },
		},
		required: ["id", "userId", "expiresAt", "createdAt", "current"],
	};

	return {
		[`${base}/sessions`]: {
			get: {
				operationId: "listSessions",
				summary: "List active sessions for the current user",
				tags: ["Sessions"],
				security: BEARER_SECURITY,
				responses: {
					...jsonOk({ type: "array", items: sessionSchema }),
					...errorResponses(true, false),
				},
			},
		},
		[`${base}/sessions/{id}`]: {
			delete: {
				operationId: "deleteSession",
				summary: "Revoke a session by ID",
				tags: ["Sessions"],
				security: BEARER_SECURITY,
				parameters: [pathParam("id", "Session ID")],
				responses: {
					"204": { description: "Session revoked" },
					...errorResponses(true, true),
				},
			},
		},
	};
}

export function apiKeysPaths(base: string): Record<string, OpenApiPathItem> {
	const apiKeySchema: OpenApiSchema = {
		type: "object",
		properties: {
			id: { type: "string" },
			name: { type: "string" },
			prefix: { type: "string", description: "First 8 characters of the key (for display)" },
			scopes: { type: "array", items: { type: "string" } },
			expiresAt: { type: "string", format: "date-time", nullable: true },
			createdAt: { type: "string", format: "date-time" },
		},
		required: ["id", "name", "prefix", "scopes", "createdAt"],
	};

	const createApiKeyResponseSchema: OpenApiSchema = {
		type: "object",
		properties: {
			...apiKeySchema.properties,
			key: { type: "string", description: "Full API key (shown once, store securely)" },
		},
		required: [...(apiKeySchema.required ?? []), "key"],
	};

	return {
		[`${base}/api-keys`]: {
			post: {
				operationId: "createApiKey",
				summary: "Create a new API key",
				tags: ["API Keys"],
				security: BEARER_SECURITY,
				requestBody: jsonBody({
					type: "object",
					properties: {
						name: { type: "string" },
						scopes: { type: "array", items: { type: "string" } },
						expiresAt: { type: "string", format: "date-time" },
					},
					required: ["name", "scopes"],
				}),
				responses: {
					...jsonOk(createApiKeyResponseSchema),
					...errorResponses(true, false),
				},
			},
			get: {
				operationId: "listApiKeys",
				summary: "List API keys for the current user",
				tags: ["API Keys"],
				security: BEARER_SECURITY,
				responses: {
					...jsonOk({ type: "array", items: apiKeySchema }),
					...errorResponses(true, false),
				},
			},
		},
		[`${base}/api-keys/{id}`]: {
			delete: {
				operationId: "deleteApiKey",
				summary: "Delete an API key",
				tags: ["API Keys"],
				security: BEARER_SECURITY,
				parameters: [pathParam("id", "API Key ID")],
				responses: {
					"204": { description: "API key deleted" },
					...errorResponses(true, true),
				},
			},
		},
		[`${base}/api-keys/{id}/rotate`]: {
			post: {
				operationId: "rotateApiKey",
				summary: "Rotate an API key, returns a new key value",
				tags: ["API Keys"],
				security: BEARER_SECURITY,
				parameters: [pathParam("id", "API Key ID")],
				responses: {
					...jsonOk(createApiKeyResponseSchema),
					...errorResponses(true, true),
				},
			},
		},
	};
}

export function webhooksPaths(base: string): Record<string, OpenApiPathItem> {
	const webhookSchema: OpenApiSchema = {
		type: "object",
		properties: {
			id: { type: "string" },
			url: { type: "string", format: "uri" },
			events: { type: "array", items: { type: "string" } },
			active: { type: "boolean" },
			createdAt: { type: "string", format: "date-time" },
		},
		required: ["id", "url", "events", "active", "createdAt"],
	};

	return {
		[`${base}/webhooks`]: {
			post: {
				operationId: "createWebhook",
				summary: "Register a webhook endpoint",
				tags: ["Webhooks"],
				security: BEARER_SECURITY,
				requestBody: jsonBody({
					type: "object",
					properties: {
						url: { type: "string", format: "uri" },
						events: { type: "array", items: { type: "string" } },
						secret: { type: "string", description: "Signing secret for HMAC verification" },
					},
					required: ["url", "events"],
				}),
				responses: {
					...jsonOk(webhookSchema),
					...errorResponses(true, false),
				},
			},
			get: {
				operationId: "listWebhooks",
				summary: "List registered webhook endpoints",
				tags: ["Webhooks"],
				security: BEARER_SECURITY,
				responses: {
					...jsonOk({ type: "array", items: webhookSchema }),
					...errorResponses(true, false),
				},
			},
		},
		[`${base}/webhooks/{id}`]: {
			delete: {
				operationId: "deleteWebhook",
				summary: "Remove a webhook endpoint",
				tags: ["Webhooks"],
				security: BEARER_SECURITY,
				parameters: [pathParam("id", "Webhook ID")],
				responses: {
					"204": { description: "Webhook removed" },
					...errorResponses(true, true),
				},
			},
		},
	};
}
