/**
 * OpenAPI 3.1 spec generation plugin for TheAuth.
 *
 * Generates a complete OpenAPI document from TheAuth's registered auth
 * endpoints. Useful for serving at `/api/kavach/openapi.json` or wiring
 * into Swagger UI / Scalar.
 *
 * @example
 * ```typescript
 * import { createOpenApiModule } from 'theauth/auth';
 *
 * const openapi = createOpenApiModule();
 * const spec = openapi.generateSpec({
 *   title: 'My App Auth API',
 *   serverUrl: 'https://api.example.com',
 *   include: ['auth', 'sessions', 'api-keys'],
 * });
 *
 * // In your request handler:
 * const response = openapi.handleRequest(request);
 * if (response) return response;
 * ```
 */

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export type EndpointGroup =
	| "agents"
	| "auth"
	| "oauth"
	| "mcp"
	| "admin"
	| "organizations"
	| "sessions"
	| "api-keys"
	| "webhooks";

export interface OpenApiConfig {
	/** API title shown in spec. Default: "TheAuth API" */
	title?: string;
	/** Spec version string. Default: "0.0.1" */
	version?: string;
	/** Short description of the API */
	description?: string;
	/** Server base URL. Default: "/" */
	serverUrl?: string;
	/** Path prefix for all TheAuth endpoints. Default: "/api/kavach" */
	basePath?: string;
	/**
	 * Limit which endpoint groups are included in the spec.
	 * When omitted all groups are included.
	 */
	include?: EndpointGroup[];
}

// ── OpenAPI 3.1 document shape (plain objects, JSON-serializable) ────────────

export interface OpenApiInfo {
	title: string;
	version: string;
	description?: string;
}

export interface OpenApiServer {
	url: string;
}

export interface OpenApiSchema {
	type?: string;
	properties?: Record<string, OpenApiSchema>;
	required?: string[];
	items?: OpenApiSchema;
	description?: string;
	example?: unknown;
	enum?: unknown[];
	format?: string;
	nullable?: boolean;
	additionalProperties?: boolean | OpenApiSchema;
	oneOf?: OpenApiSchema[];
}

export interface OpenApiMediaType {
	schema: OpenApiSchema;
}

export interface OpenApiRequestBody {
	required?: boolean;
	content: Record<string, OpenApiMediaType>;
}

export interface OpenApiResponse {
	description: string;
	content?: Record<string, OpenApiMediaType>;
}

export interface OpenApiSecurityRequirement {
	[schemeName: string]: string[];
}

export interface OpenApiOperation {
	operationId: string;
	summary: string;
	tags: string[];
	security?: OpenApiSecurityRequirement[];
	requestBody?: OpenApiRequestBody;
	responses: Record<string, OpenApiResponse>;
	parameters?: OpenApiParameter[];
}

export interface OpenApiParameter {
	name: string;
	in: "path" | "query" | "header" | "cookie";
	required?: boolean;
	schema: OpenApiSchema;
	description?: string;
}

export interface OpenApiPathItem {
	get?: OpenApiOperation;
	post?: OpenApiOperation;
	put?: OpenApiOperation;
	patch?: OpenApiOperation;
	delete?: OpenApiOperation;
}

export interface OpenApiSecurityScheme {
	type: string;
	scheme?: string;
	bearerFormat?: string;
	description?: string;
	in?: string;
	name?: string;
	flows?: Record<string, unknown>;
}

export interface OpenApiComponents {
	securitySchemes: Record<string, OpenApiSecurityScheme>;
	schemas: Record<string, OpenApiSchema>;
}

export interface OpenApiDocument {
	openapi: "3.1.0";
	info: OpenApiInfo;
	servers: OpenApiServer[];
	paths: Record<string, OpenApiPathItem>;
	components: OpenApiComponents;
	tags: Array<{ name: string; description?: string }>;
}

export interface OpenApiModule {
	/** Generate a complete OpenAPI 3.1.0 document */
	generateSpec(config?: OpenApiConfig): OpenApiDocument;
	/**
	 * Handle an HTTP request for the spec JSON.
	 *
	 * Returns a `Response` with the spec when the request path ends with
	 * `/openapi.json`. Returns `null` for any other path so the caller's
	 * routing continues normally.
	 */
	handleRequest(request: Request, config?: OpenApiConfig): Response | null;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DEFAULT_TITLE = "TheAuth API";
const DEFAULT_VERSION = "0.0.1";
const DEFAULT_SERVER_URL = "/";
const DEFAULT_BASE_PATH = "/api/kavach";

// ---------------------------------------------------------------------------
// Shared schema fragments
// ---------------------------------------------------------------------------

const ERROR_SCHEMA: OpenApiSchema = {
	type: "object",
	properties: {
		code: { type: "string", description: "Machine-readable error code" },
		message: { type: "string", description: "Human-readable error message" },
		details: {
			type: "object",
			additionalProperties: true,
			description: "Optional structured error details",
		},
	},
	required: ["code", "message"],
};

const ERROR_RESPONSE_SCHEMA: OpenApiSchema = {
	type: "object",
	properties: {
		success: { type: "boolean", example: false },
		error: ERROR_SCHEMA,
	},
	required: ["success", "error"],
};

const BEARER_SECURITY: OpenApiSecurityRequirement[] = [{ BearerAuth: [] }];

// ---------------------------------------------------------------------------
// Shared response builders
// ---------------------------------------------------------------------------

function errorResponses(
	includeAuth = true,
	includeNotFound = false,
): Record<string, OpenApiResponse> {
	const responses: Record<string, OpenApiResponse> = {
		"400": {
			description: "Invalid request body or parameters",
			content: { "application/json": { schema: ERROR_RESPONSE_SCHEMA } },
		},
	};
	if (includeAuth) {
		responses["401"] = {
			description: "Missing or invalid authentication token",
			content: { "application/json": { schema: ERROR_RESPONSE_SCHEMA } },
		};
	}
	if (includeNotFound) {
		responses["404"] = {
			description: "Resource not found",
			content: { "application/json": { schema: ERROR_RESPONSE_SCHEMA } },
		};
	}
	return responses;
}

function jsonBody(schema: OpenApiSchema, required = true): OpenApiRequestBody {
	return {
		required,
		content: { "application/json": { schema } },
	};
}

function jsonOk(schema: OpenApiSchema): Record<string, OpenApiResponse> {
	return {
		"200": {
			description: "Success",
			content: { "application/json": { schema } },
		},
	};
}

function pathParam(name: string, description?: string): OpenApiParameter {
	return {
		name,
		in: "path",
		required: true,
		schema: { type: "string" },
		...(description !== undefined ? { description } : {}),
	};
}

// ---------------------------------------------------------------------------
// Endpoint group definitions
// ---------------------------------------------------------------------------

function agentsPaths(base: string): Record<string, OpenApiPathItem> {
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

function authPaths(base: string): Record<string, OpenApiPathItem> {
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

function oauthPaths(base: string): Record<string, OpenApiPathItem> {
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

function mcpPaths(base: string): Record<string, OpenApiPathItem> {
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

function adminPaths(base: string): Record<string, OpenApiPathItem> {
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

function organizationsPaths(base: string): Record<string, OpenApiPathItem> {
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

function sessionsPaths(base: string): Record<string, OpenApiPathItem> {
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

function apiKeysPaths(base: string): Record<string, OpenApiPathItem> {
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
			key: { type: "string", description: "Full API key — shown once, store securely" },
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
				summary: "Rotate an API key — returns a new key value",
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

function webhooksPaths(base: string): Record<string, OpenApiPathItem> {
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

// ---------------------------------------------------------------------------
// Tag definitions
// ---------------------------------------------------------------------------

const ALL_TAGS: Array<{ name: string; description: string }> = [
	{ name: "Agents", description: "Agent identity management" },
	{
		name: "Auth",
		description: "Email/password, magic link, OTP, and two-factor authentication",
	},
	{ name: "OAuth", description: "Third-party OAuth provider authentication" },
	{ name: "MCP", description: "OAuth 2.1 authorization server for AI agents (RFC 8414, 7591)" },
	{ name: "Admin", description: "Administrative user management operations" },
	{
		name: "Organizations",
		description: "Multi-tenant organization management and RBAC",
	},
	{ name: "Sessions", description: "Session lifecycle management" },
	{ name: "API Keys", description: "Static API key management with permission scopes" },
	{ name: "Webhooks", description: "Webhook endpoint registration and management" },
];

const GROUP_TAG_MAP: Record<EndpointGroup, string> = {
	agents: "Agents",
	auth: "Auth",
	oauth: "OAuth",
	mcp: "MCP",
	admin: "Admin",
	organizations: "Organizations",
	sessions: "Sessions",
	"api-keys": "API Keys",
	webhooks: "Webhooks",
};

// ---------------------------------------------------------------------------
// Path builder registry
// ---------------------------------------------------------------------------

type PathBuilder = (base: string) => Record<string, OpenApiPathItem>;

const GROUP_BUILDERS: Record<EndpointGroup, PathBuilder> = {
	agents: agentsPaths,
	auth: authPaths,
	oauth: oauthPaths,
	mcp: mcpPaths,
	admin: adminPaths,
	organizations: organizationsPaths,
	sessions: sessionsPaths,
	"api-keys": apiKeysPaths,
	webhooks: webhooksPaths,
};

const ALL_GROUPS: EndpointGroup[] = [
	"agents",
	"auth",
	"oauth",
	"mcp",
	"admin",
	"organizations",
	"sessions",
	"api-keys",
	"webhooks",
];

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Create an OpenAPI module that generates TheAuth API specifications.
 *
 * The returned module is stateless and safe to share across requests.
 */
export function createOpenApiModule(): OpenApiModule {
	function generateSpec(config: OpenApiConfig = {}): OpenApiDocument {
		const title = config.title ?? DEFAULT_TITLE;
		const version = config.version ?? DEFAULT_VERSION;
		const serverUrl = config.serverUrl ?? DEFAULT_SERVER_URL;
		const basePath = config.basePath ?? DEFAULT_BASE_PATH;
		const groups = config.include ?? ALL_GROUPS;

		// Build paths from each selected group
		const paths: Record<string, OpenApiPathItem> = {};
		for (const group of groups) {
			const builder = GROUP_BUILDERS[group];
			const groupPaths = builder(basePath);
			for (const [path, item] of Object.entries(groupPaths)) {
				paths[path] = item;
			}
		}

		// Build tags — include only those for selected groups
		const selectedTagNames = new Set(groups.map((g) => GROUP_TAG_MAP[g]));
		const tags = ALL_TAGS.filter((t) => selectedTagNames.has(t.name));

		const info: OpenApiInfo = {
			title,
			version,
			...(config.description !== undefined ? { description: config.description } : {}),
		};

		return {
			openapi: "3.1.0",
			info,
			servers: [{ url: serverUrl }],
			paths,
			components: {
				securitySchemes: {
					BearerAuth: {
						type: "http",
						scheme: "bearer",
						bearerFormat: "JWT",
						description: "TheAuth session token or agent token",
					},
				},
				schemas: {
					Error: ERROR_SCHEMA,
					ErrorResponse: ERROR_RESPONSE_SCHEMA,
				},
			},
			tags,
		};
	}

	function handleRequest(request: Request, config?: OpenApiConfig): Response | null {
		const url = new URL(request.url);
		if (!url.pathname.endsWith("/openapi.json")) {
			return null;
		}

		const spec = generateSpec(config);
		return new Response(JSON.stringify(spec, null, 2), {
			status: 200,
			headers: {
				"Content-Type": "application/json",
				"Cache-Control": "public, max-age=3600",
			},
		});
	}

	return { generateSpec, handleRequest };
}
