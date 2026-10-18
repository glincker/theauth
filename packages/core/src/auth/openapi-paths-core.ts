import { BEARER_SECURITY, errorResponses, jsonBody, jsonOk, pathParam } from "./openapi-helpers.js";
import type { OpenApiPathItem, OpenApiSchema } from "./openapi-types.js";

export function mcpPaths(base: string): Record<string, OpenApiPathItem> {
	const tokenResponseSchema: OpenApiSchema = {
		type: "object",
		properties: {
			access_token: { type: "string" },
			token_type: { type: "string", enum: ["Bearer"] },
			expires_in: { type: "integer" },
			refresh_token: { type: "string" },
			scope: { type: "string" },
		},
		required: ["access_token", "token_type", "expires_in"],
	};

	return {
		[`${base}/mcp/authorize`]: {
			get: {
				operationId: "mcpAuthorize",
				summary: "OAuth 2.1 authorization endpoint (PKCE S256 required)",
				tags: ["MCP"],
				parameters: [
					{
						name: "response_type",
						in: "query",
						required: true,
						schema: { type: "string", enum: ["code"] },
					},
					{ name: "client_id", in: "query", required: true, schema: { type: "string" } },
					{ name: "redirect_uri", in: "query", required: true, schema: { type: "string" } },
					{ name: "code_challenge", in: "query", required: true, schema: { type: "string" } },
					{
						name: "code_challenge_method",
						in: "query",
						required: true,
						schema: { type: "string", enum: ["S256"] },
					},
					{ name: "scope", in: "query", required: false, schema: { type: "string" } },
					{ name: "state", in: "query", required: false, schema: { type: "string" } },
					{ name: "resource", in: "query", required: false, schema: { type: "string" } },
				],
				responses: {
					"302": { description: "Redirect to login page or callback" },
					...errorResponses(false, false),
				},
			},
		},
		[`${base}/mcp/token`]: {
			post: {
				operationId: "mcpToken",
				summary: "OAuth 2.1 token endpoint",
				tags: ["MCP"],
				requestBody: {
					required: true,
					content: {
						"application/x-www-form-urlencoded": {
							schema: {
								type: "object",
								properties: {
									grant_type: {
										type: "string",
										enum: ["authorization_code", "refresh_token"],
									},
									code: { type: "string" },
									redirect_uri: { type: "string" },
									client_id: { type: "string" },
									client_secret: { type: "string" },
									code_verifier: { type: "string" },
									refresh_token: { type: "string" },
								},
								required: ["grant_type"],
							},
						},
					},
				},
				responses: {
					...jsonOk(tokenResponseSchema),
					...errorResponses(false, false),
				},
			},
		},
		[`${base}/mcp/register`]: {
			post: {
				operationId: "mcpRegisterClient",
				summary: "Dynamic client registration (RFC 7591)",
				tags: ["MCP"],
				requestBody: jsonBody({
					type: "object",
					properties: {
						redirect_uris: { type: "array", items: { type: "string", format: "uri" } },
						client_name: { type: "string" },
						client_uri: { type: "string", format: "uri" },
						grant_types: { type: "array", items: { type: "string" } },
						scope: { type: "string" },
					},
					required: ["redirect_uris"],
				}),
				responses: {
					"201": {
						description: "Client registered",
						content: {
							"application/json": {
								schema: {
									type: "object",
									properties: {
										client_id: { type: "string" },
										client_secret: { type: "string" },
										client_id_issued_at: { type: "integer" },
									},
									required: ["client_id", "client_id_issued_at"],
								},
							},
						},
					},
					...errorResponses(false, false),
				},
			},
		},
		[`${base}/.well-known/oauth-authorization-server`]: {
			get: {
				operationId: "mcpServerMetadata",
				summary: "OAuth 2.0 Authorization Server Metadata (RFC 8414)",
				tags: ["MCP"],
				responses: {
					"200": {
						description: "Authorization server metadata",
						content: {
							"application/json": {
								schema: {
									type: "object",
									properties: {
										issuer: { type: "string" },
										authorization_endpoint: { type: "string" },
										token_endpoint: { type: "string" },
										registration_endpoint: { type: "string" },
										scopes_supported: { type: "array", items: { type: "string" } },
									},
									required: [
										"issuer",
										"authorization_endpoint",
										"token_endpoint",
										"registration_endpoint",
									],
								},
							},
						},
					},
				},
			},
		},
	};
}

export function adminPaths(base: string): Record<string, OpenApiPathItem> {
	const adminUserSchema: OpenApiSchema = {
		type: "object",
		properties: {
			id: { type: "string" },
			email: { type: "string", format: "email" },
			name: { type: "string", nullable: true },
			banned: { type: "boolean" },
			bannedReason: { type: "string", nullable: true },
			createdAt: { type: "string", format: "date-time" },
		},
		required: ["id", "email", "banned", "createdAt"],
	};

	return {
		[`${base}/admin/users`]: {
			get: {
				operationId: "adminListUsers",
				summary: "List all users (admin only)",
				tags: ["Admin"],
				security: BEARER_SECURITY,
				responses: {
					...jsonOk({ type: "array", items: adminUserSchema }),
					...errorResponses(true, false),
				},
			},
		},
		[`${base}/admin/users/{id}/ban`]: {
			post: {
				operationId: "adminBanUser",
				summary: "Ban a user account",
				tags: ["Admin"],
				security: BEARER_SECURITY,
				parameters: [pathParam("id", "User ID")],
				requestBody: jsonBody({
					type: "object",
					properties: { reason: { type: "string" } },
					required: [],
				}),
				responses: {
					"204": { description: "User banned" },
					...errorResponses(true, true),
				},
			},
		},
		[`${base}/admin/users/{id}/unban`]: {
			post: {
				operationId: "adminUnbanUser",
				summary: "Unban a user account",
				tags: ["Admin"],
				security: BEARER_SECURITY,
				parameters: [pathParam("id", "User ID")],
				responses: {
					"204": { description: "User unbanned" },
					...errorResponses(true, true),
				},
			},
		},
		[`${base}/admin/users/{id}`]: {
			delete: {
				operationId: "adminDeleteUser",
				summary: "Delete a user account permanently",
				tags: ["Admin"],
				security: BEARER_SECURITY,
				parameters: [pathParam("id", "User ID")],
				responses: {
					"204": { description: "User deleted" },
					...errorResponses(true, true),
				},
			},
		},
	};
}

export function organizationsPaths(base: string): Record<string, OpenApiPathItem> {
	const orgSchema: OpenApiSchema = {
		type: "object",
		properties: {
			id: { type: "string" },
			name: { type: "string" },
			slug: { type: "string" },
			createdAt: { type: "string", format: "date-time" },
		},
		required: ["id", "name", "slug", "createdAt"],
	};

	return {
		[`${base}/organizations`]: {
			post: {
				operationId: "createOrganization",
				summary: "Create a new organization",
				tags: ["Organizations"],
				security: BEARER_SECURITY,
				requestBody: jsonBody({
					type: "object",
					properties: {
						name: { type: "string" },
						slug: { type: "string" },
					},
					required: ["name"],
				}),
				responses: {
					...jsonOk(orgSchema),
					...errorResponses(true, false),
				},
			},
			get: {
				operationId: "listOrganizations",
				summary: "List organizations the current user belongs to",
				tags: ["Organizations"],
				security: BEARER_SECURITY,
				responses: {
					...jsonOk({ type: "array", items: orgSchema }),
					...errorResponses(true, false),
				},
			},
		},
		[`${base}/organizations/{id}/members`]: {
			post: {
				operationId: "addOrganizationMember",
				summary: "Add a member to an organization",
				tags: ["Organizations"],
				security: BEARER_SECURITY,
				parameters: [pathParam("id", "Organization ID")],
				requestBody: jsonBody({
					type: "object",
					properties: {
						userId: { type: "string" },
						role: { type: "string", enum: ["owner", "admin", "member", "viewer"] },
					},
					required: ["userId", "role"],
				}),
				responses: {
					"204": { description: "Member added" },
					...errorResponses(true, true),
				},
			},
		},
	};
}
