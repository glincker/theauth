/**
 * OpenAPI 3.1 document for the TheAuth REST API, generated from the handler's route table
 * (`listRoutes`) and the Zod shapes in `openapi-schemas.ts`. Nothing here is written per
 * route by hand except the metadata in `openapi-operations.ts`, and the generator test fails
 * when a served route has no metadata or when the checked-in `sdks/openapi.json` is stale.
 * Regenerate with `pnpm --filter @glinr/theauth exec jiti scripts/generate-openapi.ts`.
 */
import type { ZodTypeAny } from "zod";
import { listRoutes } from "./http/router.js";
import type { RouteAuthLevel, RouteSpec, TheAuthHandlerOptions } from "./http/types.js";
import type { OperationMeta, QueryParam } from "./openapi-operations.js";
import { ADMIN_API_BODIES, ADMIN_API_ROUTES, OPERATIONS } from "./openapi-operations.js";
import { COMPONENT_SCHEMAS, ErrorEnvelopeSchema } from "./openapi-schemas.js";
import type { JsonSchema, SchemaRegistry } from "./openapi-zod.js";
import { zodToJsonSchema } from "./openapi-zod.js";

export type { JsonSchema } from "./openapi-zod.js";

export interface OpenAPISpec {
	openapi: string;
	info: { title: string; version: string; description: string };
	servers: Array<{ url: string; description: string }>;
	paths: Record<string, Record<string, OpenAPIOperation>>;
	components: {
		schemas: Record<string, JsonSchema>;
		securitySchemes: Record<string, SecurityScheme>;
	};
}

interface MediaType {
	schema: JsonSchema;
}

interface OpenAPIResponse {
	description: string;
	content?: Record<string, MediaType>;
	headers?: Record<string, { schema: JsonSchema }>;
}

export interface OpenAPIOperation {
	summary: string;
	operationId: string;
	tags: string[];
	security: Array<Record<string, string[]>>;
	parameters?: Array<{
		name: string;
		in: "query" | "path";
		required: boolean;
		schema: JsonSchema;
		description?: string;
	}>;
	requestBody?: { required: boolean; content: Record<string, MediaType> };
	responses: Record<string, OpenAPIResponse>;
}

interface SecurityScheme {
	type: string;
	scheme?: string;
	bearerFormat?: string;
	description?: string;
}

export interface GenerateOpenAPIOptions {
	/** Origin the API is served from. Default `http://localhost:3000`. */
	baseUrl?: string;
	/** Path the handler is mounted under. Default `/api/theauth`. */
	basePath?: string;
	/** Contract version written to `info.version`. Bump it when the contract changes. */
	version?: string;
	/** Handler options. Routes the handler would not serve are left out. Default: every route. */
	handler?: TheAuthHandlerOptions;
	/** Include the admin API approval routes. Default true. */
	adminApi?: boolean;
}

const DEFAULT_VERSION = "2.0.0";

const SECURITY: Record<RouteAuthLevel, Array<Record<string, string[]>>> = {
	admin: [{ BearerAuth: [] }],
	agent: [{ AgentToken: [] }],
	client: [{ ClientBasic: [] }, {}],
	device: [{ DeviceCredential: [] }],
	public: [],
};

function registryOf(): Map<ZodTypeAny, string> {
	const map = new Map<ZodTypeAny, string>();
	for (const [name, schema] of Object.entries(COMPONENT_SCHEMAS)) map.set(schema, name);
	return map;
}

function envelope(data: JsonSchema): JsonSchema {
	return { type: "object", required: ["data"], properties: { data } };
}

function queryParameter(param: QueryParam): NonNullable<OpenAPIOperation["parameters"]>[number] {
	const schema: JsonSchema = { type: param.type ?? "string" };
	if (param.enum) schema.enum = param.enum;
	return { name: param.name, in: "query", required: false, schema, description: param.description };
}

function successBody(meta: OperationMeta, registry: SchemaRegistry): JsonSchema | undefined {
	if (!meta.response) return meta.bare ? { type: "object" } : undefined;
	const one = zodToJsonSchema(meta.response, registry);
	const shape: JsonSchema = meta.list ? { type: "array", items: one } : one;
	const withAlt = meta.alsoResponse
		? { oneOf: [shape, zodToJsonSchema(meta.alsoResponse, registry)] }
		: shape;
	return meta.bare ? withAlt : envelope(withAlt);
}

function formBody(form: NonNullable<OperationMeta["form"]>): JsonSchema {
	const properties: Record<string, JsonSchema> = {};
	for (const [name, description] of Object.entries(form.fields)) {
		properties[name] = { type: "string", description };
	}
	return { type: "object", required: form.required, properties };
}

function buildResponses(
	meta: OperationMeta,
	registry: SchemaRegistry,
	auth: RouteAuthLevel,
): Record<string, OpenAPIResponse> {
	const responses: Record<string, OpenAPIResponse> = {};
	const body = successBody(meta, registry);
	if (meta.redirect) {
		responses[String(meta.status)] = {
			description: "Redirect to the login page or back to the client",
			headers: { Location: { schema: { type: "string" } } },
		};
	} else if (meta.textType) {
		responses[String(meta.status)] = {
			description: "Exported entries",
			content: {
				[meta.textType]: { schema: { type: "string" } },
				"application/json": { schema: { type: "string" } },
			},
		};
	} else {
		responses[String(meta.status)] = {
			description: "Success",
			...(body ? { content: { "application/json": { schema: body } } } : {}),
		};
	}
	for (const status of meta.resultStatuses ?? []) {
		responses[String(status)] = {
			description:
				"Decision made, the call is not allowed. The body is the same result as on success.",
			...(body ? { content: { "application/json": { schema: body } } } : {}),
		};
	}
	const errorBody = {
		"application/json": { schema: zodToJsonSchema(ErrorEnvelopeSchema, registry) },
	};
	for (const [status, description] of Object.entries(meta.errors ?? {})) {
		if (!responses[status]) responses[status] = { description, content: errorBody };
	}
	if (auth === "admin") {
		const common: Array<[string, string]> = [
			["401", "Not signed in"],
			["403", "Outside the caller's scope"],
		];
		for (const [status, description] of common) {
			if (!responses[status]) responses[status] = { description, content: errorBody };
		}
	}
	return responses;
}

function buildOperation(
	route: RouteSpec,
	meta: OperationMeta,
	registry: SchemaRegistry,
	bodySchema: JsonSchema | undefined,
): OpenAPIOperation {
	const params = [...route.path.matchAll(/:([A-Za-z0-9_]+)/g)].map((m) => m[1] as string);
	const parameters = [
		...params.map((name) => ({
			name,
			in: "path" as const,
			required: true,
			schema: { type: "string" } as JsonSchema,
		})),
		...(meta.query ?? []).map(queryParameter),
	];
	const op: OpenAPIOperation = {
		summary: route.summary,
		operationId: meta.operationId,
		tags: [meta.tag],
		security: SECURITY[route.auth],
		responses: buildResponses(meta, registry, route.auth),
	};
	if (parameters.length > 0) op.parameters = parameters;
	if (meta.form) {
		op.requestBody = {
			required: true,
			content: { "application/x-www-form-urlencoded": { schema: formBody(meta.form) } },
		};
	} else if (bodySchema || meta.openBody) {
		op.requestBody = {
			required: true,
			content: { "application/json": { schema: bodySchema ?? { type: "object" } } },
		};
	}
	return op;
}

/** Generate the OpenAPI 3.1 document for the routes `options.handler` would serve. */
export function generateOpenAPISpec(options: GenerateOpenAPIOptions = {}): OpenAPISpec {
	const baseUrl = options.baseUrl ?? "http://localhost:3000";
	const basePath = options.basePath ?? options.handler?.basePath ?? "/api/theauth";
	const registry = registryOf();
	const routes: Array<{ route: RouteSpec; body?: JsonSchema }> = listRoutes(options.handler).map(
		(route) => ({
			route,
			body: route.body ? zodToJsonSchema(route.body, registry) : undefined,
		}),
	);
	if (options.adminApi !== false) {
		for (const route of ADMIN_API_ROUTES) {
			const schema = ADMIN_API_BODIES[`${route.method} ${route.path}`];
			routes.push({ route, body: schema ? zodToJsonSchema(schema, registry) : undefined });
		}
	}

	const paths: OpenAPISpec["paths"] = {};
	for (const { route, body } of routes) {
		const key = `${route.method} ${route.path}`;
		const meta = OPERATIONS[key];
		if (!meta) throw new Error(`openapi: no operation metadata for ${key}`);
		const path = route.path.replace(/:([A-Za-z0-9_]+)/g, "{$1}");
		const methods = paths[path] ?? {};
		methods[route.method.toLowerCase()] = buildOperation(route, meta, registry, body);
		paths[path] = methods;
	}

	const schemas: Record<string, JsonSchema> = {};
	for (const [name, schema] of Object.entries(COMPONENT_SCHEMAS)) {
		schemas[name] = zodToJsonSchema(schema, registry, true);
	}

	return {
		openapi: "3.1.0",
		info: {
			title: "TheAuth API",
			version: options.version ?? DEFAULT_VERSION,
			description:
				"The Auth OS for AI Agents. Identity, permissions, delegation, and audit for the agentic era. Generated from the route table of createTheAuthHandler.",
		},
		servers: [{ url: `${baseUrl}${basePath}`, description: "TheAuth API Server" }],
		paths,
		components: {
			schemas,
			securitySchemes: {
				BearerAuth: {
					type: "http",
					scheme: "bearer",
					description: "A signed-in user session, or the principal your authenticate hook resolves",
				},
				AgentToken: {
					type: "http",
					scheme: "bearer",
					bearerFormat: "TheAuth Agent Token (ta_...)",
				},
				DeviceCredential: {
					type: "http",
					scheme: "bearer",
					description:
						"A device pre shared key (tdk_...) or a device assertion JWT (typ device-assertion+jwt). A client certificate checked by your proxy also works when devices.clientCertThumbprint is set.",
				},
				ClientBasic: {
					type: "http",
					scheme: "basic",
					description:
						"OAuth client credentials. client_secret_post and private_key_jwt are also accepted in the form body.",
				},
			},
		},
	};
}
