import { createAgentModule } from "../agent/agent.js";
import type { TheAuthPlugin } from "../plugin/types.js";
import type { Permission } from "../types.js";
import type {
	AgentRegistrationEvent,
	AgentType,
	RegistrationTokenStatus,
} from "./agent-registration.js";
import { createAgentRegistrationModule } from "./agent-registration.js";
import type { ResolvedUser } from "./types.js";

export interface AgentRegistrationPluginConfig {
	/**
	 * Decide whether a signed-in user is an admin. Admins can mint, list and
	 * revoke tokens for any owner. Everyone else can only manage their own.
	 * Default: nobody is admin.
	 */
	isAdmin?: (user: ResolvedUser) => boolean | Promise<boolean>;
	defaultExpiresInSeconds?: number;
	maxExpiresInSeconds?: number;
	onEvent?: (event: AgentRegistrationEvent) => void | Promise<void>;
}

function json(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
	});
}

function bearer(request: Request): string | null {
	const h = request.headers.get("authorization");
	return h?.toLowerCase().startsWith("bearer ") ? h.slice(7).trim() : null;
}

async function readJson(request: Request): Promise<Record<string, unknown>> {
	try {
		const body: unknown = await request.json();
		return body && typeof body === "object" ? (body as Record<string, unknown>) : {};
	} catch {
		return {};
	}
}

/**
 * Mounts:
 * - POST   /auth/agent-registration/register  (bearer registration token, no session)
 * - POST   /auth/agent-registration/tokens    (signed in)
 * - GET    /auth/agent-registration/tokens    (signed in)
 * - DELETE /auth/agent-registration/tokens/:id (signed in)
 */
export function agentRegistration(config: AgentRegistrationPluginConfig = {}): TheAuthPlugin {
	return {
		id: "theauth-agent-registration",

		async init(ctx): Promise<{ context: Record<string, unknown> }> {
			const agents = createAgentModule({
				db: ctx.db,
				maxPerUser: ctx.config.agents?.maxPerUser ?? 10,
				defaultPermissions: ctx.config.agents?.defaultPermissions ?? [],
				tokenExpiry: ctx.config.agents?.tokenExpiry ?? "24h",
			});
			const hooks = ctx.config.hooks;
			const mod = createAgentRegistrationModule({
				...config,
				db: ctx.db,
				// Same lifecycle hooks as theauth.agent.create, so policy still applies.
				agents: {
					async create(input) {
						const verdict = await hooks?.beforeAgentCreate?.(input);
						if (verdict && !verdict.allow) {
							throw new Error(verdict.reason ?? "Agent creation blocked by beforeAgentCreate hook");
						}
						const agent = await agents.create(input);
						void hooks?.afterAgentCreate?.(agent);
						return agent;
					},
				},
			});
			const isAdmin = async (u: ResolvedUser) => (config.isAdmin ? await config.isAdmin(u) : false);
			const unauth = () => json({ error: "login_required" }, 401);

			ctx.addEndpoint({
				method: "POST",
				path: "/auth/agent-registration/register",
				metadata: {
					description: "Redeem a one-time registration token to create an agent identity",
					rateLimit: { window: 60, max: 20 },
				},
				async handler(request) {
					const token = bearer(request);
					if (!token) return json({ error: "invalid_token" }, 401);
					const body = await readJson(request);
					const metadata =
						body.metadata && typeof body.metadata === "object"
							? (body.metadata as Record<string, unknown>)
							: undefined;
					const result = await mod.redeem(token, {
						name: typeof body.name === "string" ? body.name : "",
						metadata,
					});
					if (!result.success) {
						const status = result.error.code === "INVALID_TOKEN" ? 401 : 400;
						return json(
							{ error: result.error.code, error_description: result.error.message },
							status,
						);
					}
					const a = result.data;
					return json(
						{
							agent_id: a.id,
							name: a.name,
							token: a.token,
							permissions: a.permissions,
							expires_at: a.expiresAt?.toISOString() ?? null,
						},
						201,
					);
				},
			});

			ctx.addEndpoint({
				method: "POST",
				path: "/auth/agent-registration/tokens",
				metadata: { requireAuth: true, description: "Mint a registration token" },
				async handler(request, ectx) {
					const user = await ectx.getUser(request);
					if (!user) return unauth();
					const body = await readJson(request);
					const admin = await isAdmin(user);
					const ownerId = typeof body.owner_id === "string" ? body.owner_id : user.id;
					if (ownerId !== user.id && !admin) {
						return json(
							{ error: "forbidden", error_description: "Only admins can mint for other owners" },
							403,
						);
					}
					if (!Array.isArray(body.permissions)) {
						return json(
							{ error: "invalid_request", error_description: "permissions must be an array" },
							400,
						);
					}
					const result = await mod.create({
						ownerId,
						permissions: body.permissions as Permission[],
						label: typeof body.label === "string" ? body.label : undefined,
						agentType:
							typeof body.agent_type === "string" ? (body.agent_type as AgentType) : undefined,
						namePrefix: typeof body.name_prefix === "string" ? body.name_prefix : undefined,
						expiresInSeconds: typeof body.expires_in === "number" ? body.expires_in : undefined,
						agentTtlSeconds:
							typeof body.agent_ttl_seconds === "number" ? body.agent_ttl_seconds : undefined,
						createdBy: user.id,
					});
					if (!result.success) {
						return json({ error: result.error.code, error_description: result.error.message }, 400);
					}
					return json(
						{
							id: result.data.id,
							token: result.data.token,
							prefix: result.data.prefix,
							expires_at: result.data.expiresAt.toISOString(),
						},
						201,
					);
				},
			});

			ctx.addEndpoint({
				method: "GET",
				path: "/auth/agent-registration/tokens",
				metadata: { requireAuth: true, description: "List registration tokens" },
				async handler(request, ectx) {
					const user = await ectx.getUser(request);
					if (!user) return unauth();
					const status = new URL(request.url).searchParams.get(
						"status",
					) as RegistrationTokenStatus | null;
					const records = await mod.list({
						ownerId: (await isAdmin(user)) ? undefined : user.id,
						status: status ?? undefined,
					});
					return json({ tokens: records });
				},
			});

			ctx.addEndpoint({
				method: "DELETE",
				path: "/auth/agent-registration/tokens/:id",
				metadata: { requireAuth: true, description: "Revoke a registration token" },
				async handler(request, ectx) {
					const user = await ectx.getUser(request);
					if (!user) return unauth();
					const id = new URL(request.url).searchParams.get("_param_id") ?? "";
					if (!(await isAdmin(user))) {
						const own = await mod.list({ ownerId: user.id });
						if (!own.some((t) => t.id === id)) return json({ error: "TOKEN_NOT_FOUND" }, 404);
					}
					const result = await mod.revoke(id, user.id);
					if (!result.success) {
						return json(
							{ error: result.error.code, error_description: result.error.message },
							result.error.code === "TOKEN_NOT_FOUND" ? 404 : 400,
						);
					}
					return json({ revoked: true, id });
				},
			});

			return { context: { agentRegistration: mod } };
		},
	};
}
