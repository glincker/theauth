/**
 * OpenAPI 3.1 specification generator for TheAuth REST API.
 *
 * This generates the spec that enables auto-generated SDKs
 * for Python, Go, Java, Rust, etc. via OpenAPI codegen tools.
 */

export interface OpenAPISpec {
	openapi: string;
	info: { title: string; version: string; description: string };
	servers: Array<{ url: string; description: string }>;
	paths: Record<string, Record<string, PathOperation>>;
	components: {
		schemas: Record<string, SchemaObject>;
		securitySchemes: Record<string, SecurityScheme>;
	};
}

interface PathOperation {
	summary: string;
	operationId: string;
	tags: string[];
	security?: Array<Record<string, string[]>>;
	parameters?: ParameterObject[];
	requestBody?: { required: boolean; content: Record<string, { schema: SchemaRef }> };
	responses: Record<
		string,
		{ description: string; content?: Record<string, { schema: SchemaRef }> }
	>;
}

interface ParameterObject {
	name: string;
	in: "query" | "path" | "header";
	required: boolean;
	schema: SchemaRef;
}

interface SecurityScheme {
	type: string;
	scheme?: string;
	bearerFormat?: string;
}

type SchemaRef = { $ref: string } | SchemaObject;

interface SchemaObject {
	type?: string;
	properties?: Record<string, SchemaRef>;
	required?: string[];
	items?: SchemaRef;
	enum?: string[];
	description?: string;
	format?: string;
	nullable?: boolean;
}

/**
 * Generate the full OpenAPI 3.1 specification for the TheAuth REST API.
 */
export function generateOpenAPISpec(options?: { baseUrl?: string; version?: string }): OpenAPISpec {
	const baseUrl = options?.baseUrl ?? "http://localhost:3000";
	const version = options?.version ?? "0.0.1";

	return {
		openapi: "3.1.0",
		info: {
			title: "TheAuth API",
			version,
			description:
				"The Auth OS for AI Agents. Identity, permissions, delegation, and audit for the agentic era.",
		},
		servers: [{ url: baseUrl, description: "TheAuth API Server" }],
		paths: {
			"/agents": {
				post: {
					summary: "Create a new agent",
					operationId: "createAgent",
					tags: ["Agents"],
					security: [{ BearerAuth: [] }],
					requestBody: {
						required: true,
						content: {
							"application/json": { schema: { $ref: "#/components/schemas/CreateAgentInput" } },
						},
					},
					responses: {
						"201": {
							description: "Agent created",
							content: {
								"application/json": {
									schema: { $ref: "#/components/schemas/AgentWithToken" },
								},
							},
						},
						"400": { description: "Invalid input" },
						"429": { description: "Max agents per user exceeded" },
					},
				},
				get: {
					summary: "List agents",
					operationId: "listAgents",
					tags: ["Agents"],
					security: [{ BearerAuth: [] }],
					parameters: [
						{ name: "userId", in: "query", required: false, schema: { type: "string" } },
						{
							name: "status",
							in: "query",
							required: false,
							schema: { type: "string", enum: ["active", "revoked", "expired"] },
						},
						{
							name: "type",
							in: "query",
							required: false,
							schema: { type: "string", enum: ["autonomous", "delegated", "service"] },
						},
					],
					responses: {
						"200": {
							description: "List of agents",
							content: {
								"application/json": {
									schema: { type: "array", items: { $ref: "#/components/schemas/Agent" } },
								},
							},
						},
					},
				},
			},
			"/agents/{id}": {
				get: {
					summary: "Get agent by ID",
					operationId: "getAgent",
					tags: ["Agents"],
					security: [{ BearerAuth: [] }],
					parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
					responses: {
						"200": {
							description: "Agent details",
							content: { "application/json": { schema: { $ref: "#/components/schemas/Agent" } } },
						},
						"404": { description: "Agent not found" },
					},
				},
				patch: {
					summary: "Update agent",
					operationId: "updateAgent",
					tags: ["Agents"],
					security: [{ BearerAuth: [] }],
					parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
					requestBody: {
						required: true,
						content: {
							"application/json": { schema: { $ref: "#/components/schemas/UpdateAgentInput" } },
						},
					},
					responses: {
						"200": {
							description: "Agent updated",
							content: { "application/json": { schema: { $ref: "#/components/schemas/Agent" } } },
						},
					},
				},
				delete: {
					summary: "Revoke agent",
					operationId: "revokeAgent",
					tags: ["Agents"],
					security: [{ BearerAuth: [] }],
					parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
					responses: { "204": { description: "Agent revoked" } },
				},
			},
			"/agents/{id}/rotate": {
				post: {
					summary: "Rotate agent token",
					operationId: "rotateAgentToken",
					tags: ["Agents"],
					security: [{ BearerAuth: [] }],
					parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
					responses: {
						"200": {
							description: "New token issued",
							content: {
								"application/json": { schema: { $ref: "#/components/schemas/AgentWithToken" } },
							},
						},
					},
				},
			},
			"/authorize": {
				post: {
					summary: "Authorize an agent action",
					operationId: "authorize",
					tags: ["Authorization"],
					requestBody: {
						required: true,
						content: {
							"application/json": { schema: { $ref: "#/components/schemas/AuthorizeRequest" } },
						},
					},
					responses: {
						"200": {
							description: "Authorization result",
							content: {
								"application/json": { schema: { $ref: "#/components/schemas/AuthorizeResult" } },
							},
						},
					},
				},
			},
			"/authorize/token": {
				post: {
					summary: "Authorize by agent token",
					operationId: "authorizeByToken",
					tags: ["Authorization"],
					security: [{ AgentToken: [] }],
					requestBody: {
						required: true,
						content: {
							"application/json": {
								schema: {
									type: "object",
									properties: {
										action: { type: "string" },
										resource: { type: "string" },
										arguments: { type: "object" },
									},
									required: ["action", "resource"],
								},
							},
						},
					},
					responses: {
						"200": {
							description: "Authorization result",
							content: {
								"application/json": { schema: { $ref: "#/components/schemas/AuthorizeResult" } },
							},
						},
					},
				},
			},
			"/audit": {
				get: {
					summary: "Query audit logs",
					operationId: "queryAudit",
					tags: ["Audit"],
					security: [{ BearerAuth: [] }],
					parameters: [
						{ name: "agentId", in: "query", required: false, schema: { type: "string" } },
						{ name: "userId", in: "query", required: false, schema: { type: "string" } },
						{
							name: "since",
							in: "query",
							required: false,
							schema: { type: "string", format: "date-time" },
						},
						{
							name: "until",
							in: "query",
							required: false,
							schema: { type: "string", format: "date-time" },
						},
						{
							name: "result",
							in: "query",
							required: false,
							schema: { type: "string", enum: ["allowed", "denied", "rate_limited"] },
						},
						{ name: "limit", in: "query", required: false, schema: { type: "integer" } },
						{ name: "offset", in: "query", required: false, schema: { type: "integer" } },
					],
					responses: {
						"200": {
							description: "Audit log entries",
							content: {
								"application/json": {
									schema: { type: "array", items: { $ref: "#/components/schemas/AuditEntry" } },
								},
							},
						},
					},
				},
			},
			"/delegations": {
				post: {
					summary: "Create delegation chain",
					operationId: "createDelegation",
					tags: ["Delegation"],
					security: [{ BearerAuth: [] }],
					requestBody: {
						required: true,
						content: {
							"application/json": { schema: { $ref: "#/components/schemas/DelegateInput" } },
						},
					},
					responses: {
						"201": {
							description: "Delegation created",
							content: {
								"application/json": { schema: { $ref: "#/components/schemas/DelegationChain" } },
							},
						},
					},
				},
			},
		},
		components: {
			schemas: {
				CreateAgentInput: {
					type: "object",
					required: ["ownerId", "name", "type", "permissions"],
					properties: {
						ownerId: { type: "string" },
						name: { type: "string" },
						type: { type: "string", enum: ["autonomous", "delegated", "service"] },
						permissions: { type: "array", items: { $ref: "#/components/schemas/Permission" } },
						expiresAt: { type: "string", format: "date-time", nullable: true },
						metadata: { type: "object" },
					},
				},
				UpdateAgentInput: {
					type: "object",
					properties: {
						name: { type: "string" },
						permissions: { type: "array", items: { $ref: "#/components/schemas/Permission" } },
						expiresAt: { type: "string", format: "date-time", nullable: true },
						metadata: { type: "object" },
					},
				},
				Agent: {
					type: "object",
					properties: {
						id: { type: "string" },
						ownerId: { type: "string" },
						name: { type: "string" },
						type: { type: "string", enum: ["autonomous", "delegated", "service"] },
						status: { type: "string", enum: ["active", "revoked", "expired"] },
						permissions: { type: "array", items: { $ref: "#/components/schemas/Permission" } },
						expiresAt: { type: "string", format: "date-time", nullable: true },
						createdAt: { type: "string", format: "date-time" },
						updatedAt: { type: "string", format: "date-time" },
					},
				},
				AgentWithToken: {
					type: "object",
					description: "Agent identity with the token (only returned on create/rotate)",
					properties: {
						id: { type: "string" },
						token: {
							type: "string",
							description:
								"Agent token (kv_ prefix). Store securely - not retrievable after creation.",
						},
						name: { type: "string" },
						type: { type: "string" },
						status: { type: "string" },
						permissions: { type: "array", items: { $ref: "#/components/schemas/Permission" } },
					},
				},
				Permission: {
					type: "object",
					required: ["resource", "actions"],
					properties: {
						resource: {
							type: "string",
							description: "Resource pattern (e.g. mcp:github:*, tool:file_read)",
						},
						actions: {
							type: "array",
							items: { type: "string" },
							description: "Allowed actions (read, write, execute, delete, *)",
						},
						constraints: { $ref: "#/components/schemas/PermissionConstraints" },
					},
				},
				PermissionConstraints: {
					type: "object",
					properties: {
						maxCallsPerHour: { type: "integer" },
						allowedArgPatterns: { type: "array", items: { type: "string" } },
						requireApproval: { type: "boolean" },
						timeWindow: {
							type: "object",
							properties: {
								start: { type: "string", description: "HH:MM format" },
								end: { type: "string", description: "HH:MM format" },
							},
						},
						ipAllowlist: { type: "array", items: { type: "string" } },
					},
				},
				AuthorizeRequest: {
					type: "object",
					required: ["agentId", "action", "resource"],
					properties: {
						agentId: { type: "string" },
						action: { type: "string" },
						resource: { type: "string" },
						arguments: { type: "object" },
					},
				},
				AuthorizeResult: {
					type: "object",
					properties: {
						allowed: { type: "boolean" },
						reason: { type: "string", nullable: true },
						auditId: { type: "string" },
					},
				},
				AuditEntry: {
					type: "object",
					properties: {
						id: { type: "string" },
						agentId: { type: "string" },
						userId: { type: "string" },
						action: { type: "string" },
						resource: { type: "string" },
						parameters: { type: "object" },
						result: { type: "string", enum: ["allowed", "denied", "rate_limited"] },
						durationMs: { type: "integer" },
						timestamp: { type: "string", format: "date-time" },
					},
				},
				DelegateInput: {
					type: "object",
					required: ["fromAgent", "toAgent", "permissions", "expiresAt"],
					properties: {
						fromAgent: { type: "string" },
						toAgent: { type: "string" },
						permissions: { type: "array", items: { $ref: "#/components/schemas/Permission" } },
						expiresAt: { type: "string", format: "date-time" },
						maxDepth: { type: "integer" },
					},
				},
				DelegationChain: {
					type: "object",
					properties: {
						id: { type: "string" },
						fromAgent: { type: "string" },
						toAgent: { type: "string" },
						permissions: { type: "array", items: { $ref: "#/components/schemas/Permission" } },
						depth: { type: "integer" },
						expiresAt: { type: "string", format: "date-time" },
						createdAt: { type: "string", format: "date-time" },
					},
				},
			},
			securitySchemes: {
				BearerAuth: {
					type: "http",
					scheme: "bearer",
					bearerFormat: "JWT",
				},
				AgentToken: {
					type: "http",
					scheme: "bearer",
					bearerFormat: "TheAuth Agent Token (kv_...)",
				},
			},
		},
	};
}
