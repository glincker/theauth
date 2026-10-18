/**
 * OpenAPI 3.1 spec generation plugin for TheAuth.
 *
 * @example
 * ```typescript
 * import { createOpenApiModule } from '@glinr/theauth/auth';
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

export type {
	EndpointGroup,
	OpenApiComponents,
	OpenApiConfig,
	OpenApiDocument,
	OpenApiInfo,
	OpenApiMediaType,
	OpenApiModule,
	OpenApiOperation,
	OpenApiParameter,
	OpenApiPathItem,
	OpenApiRequestBody,
	OpenApiResponse,
	OpenApiSchema,
	OpenApiSecurityRequirement,
	OpenApiSecurityScheme,
	OpenApiServer,
} from "./openapi-types.js";

import {
	DEFAULT_BASE_PATH,
	DEFAULT_SERVER_URL,
	DEFAULT_TITLE,
	DEFAULT_VERSION,
	ERROR_RESPONSE_SCHEMA,
	ERROR_SCHEMA,
} from "./openapi-helpers.js";
import { agentsPaths, authPaths, oauthPaths } from "./openapi-paths-auth.js";
import { adminPaths, mcpPaths, organizationsPaths } from "./openapi-paths-core.js";
import { apiKeysPaths, sessionsPaths, webhooksPaths } from "./openapi-paths-resources.js";
import type {
	EndpointGroup,
	OpenApiConfig,
	OpenApiDocument,
	OpenApiInfo,
	OpenApiModule,
	OpenApiPathItem,
} from "./openapi-types.js";

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

/**
 * Create an OpenAPI module that generates TheAuth API specifications.
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

		// Build tags, include only those for selected groups
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
