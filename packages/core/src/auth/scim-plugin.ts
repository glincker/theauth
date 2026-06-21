import type { KavachPlugin } from "../plugin/types.js";
import type { ScimConfig } from "./scim.js";
import { createScimModule } from "./scim.js";

export type { ScimConfig };

// ---------------------------------------------------------------------------
// Plugin factory
// ---------------------------------------------------------------------------

/**
 * SCIM 2.0 directory sync plugin for TheAuth.
 *
 * Mounts SCIM endpoints under `/scim/v2/` so enterprise IdPs (Okta, Azure AD,
 * Google Workspace) can provision and deprovision users and groups.
 *
 * All endpoints require a static Bearer token supplied via `config.bearerToken`.
 *
 * @example
 * ```typescript
 * import { createKavach } from '@glinr/theauth';
 * import { scim } from '@glinr/theauth/auth';
 *
 * const kavach = await createKavach({
 *   database: { provider: 'sqlite', url: 'kavach.db' },
 *   plugins: [
 *     scim({
 *       bearerToken: process.env.SCIM_TOKEN,
 *       onProvision: async (user) => {
 *         await sendWelcomeEmail(user.emails?.[0]?.value);
 *       },
 *     }),
 *   ],
 * });
 * ```
 */
export function scim(config: ScimConfig): KavachPlugin {
	return {
		id: "kavach-scim",

		async init(ctx): Promise<undefined> {
			const module = createScimModule(config, ctx.db);

			// We register a single catch-all GET handler per method and let the
			// module's internal router do path matching. The plugin endpoint
			// system uses exact path matching, so we register wildcard-style
			// paths for each SCIM sub-resource and method combination.
			//
			// Discovery
			ctx.addEndpoint({
				method: "GET",
				path: "/scim/v2/ServiceProviderConfig",
				metadata: { description: "SCIM service provider configuration (RFC 7643)" },
				async handler(request) {
					return (await module.handleRequest(request)) as Response;
				},
			});

			ctx.addEndpoint({
				method: "GET",
				path: "/scim/v2/Schemas",
				metadata: { description: "SCIM schema definitions" },
				async handler(request) {
					return (await module.handleRequest(request)) as Response;
				},
			});

			ctx.addEndpoint({
				method: "GET",
				path: "/scim/v2/ResourceTypes",
				metadata: { description: "SCIM resource type definitions" },
				async handler(request) {
					return (await module.handleRequest(request)) as Response;
				},
			});

			// Users collection
			ctx.addEndpoint({
				method: "GET",
				path: "/scim/v2/Users",
				metadata: { description: "List SCIM users (RFC 7644)" },
				async handler(request) {
					return (await module.handleRequest(request)) as Response;
				},
			});

			ctx.addEndpoint({
				method: "POST",
				path: "/scim/v2/Users",
				metadata: { description: "Create (provision) a SCIM user" },
				async handler(request) {
					return (await module.handleRequest(request)) as Response;
				},
			});

			// Users by ID
			ctx.addEndpoint({
				method: "GET",
				path: "/scim/v2/Users/:id",
				metadata: { description: "Get a SCIM user by ID" },
				async handler(request) {
					return (await module.handleRequest(request)) as Response;
				},
			});

			ctx.addEndpoint({
				method: "PUT",
				path: "/scim/v2/Users/:id",
				metadata: { description: "Replace a SCIM user" },
				async handler(request) {
					return (await module.handleRequest(request)) as Response;
				},
			});

			ctx.addEndpoint({
				method: "PATCH",
				path: "/scim/v2/Users/:id",
				metadata: { description: "Partially update a SCIM user" },
				async handler(request) {
					return (await module.handleRequest(request)) as Response;
				},
			});

			ctx.addEndpoint({
				method: "DELETE",
				path: "/scim/v2/Users/:id",
				metadata: { description: "Deprovision a SCIM user" },
				async handler(request) {
					return (await module.handleRequest(request)) as Response;
				},
			});

			// Groups collection
			ctx.addEndpoint({
				method: "GET",
				path: "/scim/v2/Groups",
				metadata: { description: "List SCIM groups (mapped to organizations)" },
				async handler(request) {
					return (await module.handleRequest(request)) as Response;
				},
			});

			ctx.addEndpoint({
				method: "POST",
				path: "/scim/v2/Groups",
				metadata: { description: "Create a SCIM group" },
				async handler(request) {
					return (await module.handleRequest(request)) as Response;
				},
			});

			// Groups by ID
			ctx.addEndpoint({
				method: "GET",
				path: "/scim/v2/Groups/:id",
				metadata: { description: "Get a SCIM group by ID" },
				async handler(request) {
					return (await module.handleRequest(request)) as Response;
				},
			});

			ctx.addEndpoint({
				method: "PUT",
				path: "/scim/v2/Groups/:id",
				metadata: { description: "Replace a SCIM group" },
				async handler(request) {
					return (await module.handleRequest(request)) as Response;
				},
			});

			ctx.addEndpoint({
				method: "PATCH",
				path: "/scim/v2/Groups/:id",
				metadata: { description: "Partially update a SCIM group" },
				async handler(request) {
					return (await module.handleRequest(request)) as Response;
				},
			});

			ctx.addEndpoint({
				method: "DELETE",
				path: "/scim/v2/Groups/:id",
				metadata: { description: "Delete a SCIM group" },
				async handler(request) {
					return (await module.handleRequest(request)) as Response;
				},
			});
		},
	};
}
