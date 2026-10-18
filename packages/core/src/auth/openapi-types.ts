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
	/** Path prefix for all TheAuth endpoints. Default: "/api/theauth" */
	basePath?: string;
	/** Limit which endpoint groups are included in the spec. When omitted all groups are included. */
	include?: EndpointGroup[];
}

// OpenAPI 3.1 document shape (plain objects, JSON-serializable)

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
	 * Returns a `Response` with the spec when the request path ends with `/openapi.json`.
	 */
	handleRequest(request: Request, config?: OpenApiConfig): Response | null;
}
