import type {
	OpenApiParameter,
	OpenApiRequestBody,
	OpenApiResponse,
	OpenApiSchema,
	OpenApiSecurityRequirement,
} from "./openapi-types.js";

export const DEFAULT_TITLE = "TheAuth API";
export const DEFAULT_VERSION = "0.0.1";
export const DEFAULT_SERVER_URL = "/";
export const DEFAULT_BASE_PATH = "/api/theauth";

export const ERROR_SCHEMA: OpenApiSchema = {
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

export const ERROR_RESPONSE_SCHEMA: OpenApiSchema = {
	type: "object",
	properties: {
		success: { type: "boolean", example: false },
		error: ERROR_SCHEMA,
	},
	required: ["success", "error"],
};

export const BEARER_SECURITY: OpenApiSecurityRequirement[] = [{ BearerAuth: [] }];

export function errorResponses(
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

export function jsonBody(schema: OpenApiSchema, required = true): OpenApiRequestBody {
	return {
		required,
		content: { "application/json": { schema } },
	};
}

export function jsonOk(schema: OpenApiSchema): Record<string, OpenApiResponse> {
	return {
		"200": {
			description: "Success",
			content: { "application/json": { schema } },
		},
	};
}

export function pathParam(name: string, description?: string): OpenApiParameter {
	return {
		name,
		in: "path",
		required: true,
		schema: { type: "string" },
		...(description !== undefined ? { description } : {}),
	};
}
