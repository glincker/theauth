import type { ResolvedUser } from "../auth/types.js";
import { json } from "../plugin/helpers.js";
import type { TheAuthPlugin } from "../plugin/types.js";
import type { Permission } from "../types.js";
import { createSimulator } from "./simulate.js";
import type { SimulateInput, SimulationContext, SimulationOverrides } from "./types.js";

export interface SimulatorPluginConfig {
	/** Decide whether a signed-in user may simulate. Default: nobody, so the route stays closed. */
	isAdmin?: (user: ResolvedUser) => boolean | Promise<boolean>;
}

const ROUTE = /^\/agents\/([^/]+)\/simulate\/?$/;

function isRecord(v: unknown): v is Record<string, unknown> {
	return typeof v === "object" && v !== null && !Array.isArray(v);
}

function str(v: unknown): string | undefined {
	return typeof v === "string" && v !== "" ? v : undefined;
}

function strList(v: unknown): string[] | undefined {
	return Array.isArray(v) && v.every((x) => typeof x === "string" && x !== "")
		? (v as string[])
		: undefined;
}

function date(v: unknown): Date | undefined {
	if (typeof v !== "string") return undefined;
	const d = new Date(v);
	return Number.isNaN(d.getTime()) ? undefined : d;
}

function perms(v: unknown): Permission[] | undefined {
	if (!Array.isArray(v)) return undefined;
	const out: Permission[] = [];
	for (const p of v) {
		if (!isRecord(p) || typeof p.resource !== "string" || !strList(p.actions)) return undefined;
		out.push({
			resource: p.resource,
			actions: p.actions as string[],
			constraints: isRecord(p.constraints)
				? (p.constraints as Permission["constraints"])
				: undefined,
		});
	}
	return out;
}

function parseContext(v: unknown): SimulationContext | undefined {
	if (!isRecord(v)) return undefined;
	return {
		ip: str(v.ip),
		arguments: isRecord(v.arguments) ? v.arguments : undefined,
		timestamp: date(v.timestamp),
	};
}

function parseOverrides(v: unknown): SimulationOverrides | undefined {
	if (!isRecord(v)) return undefined;
	const chains = Array.isArray(v.delegationChains)
		? v.delegationChains.flatMap((c) => {
				if (!isRecord(c)) return [];
				const permissions = perms(c.permissions);
				if (!permissions) return [];
				return [
					{
						id: str(c.id),
						permissions,
						depth: typeof c.depth === "number" ? c.depth : undefined,
						maxDepth: typeof c.maxDepth === "number" ? c.maxDepth : undefined,
						expiresAt: date(c.expiresAt),
					},
				];
			})
		: undefined;
	const b = isRecord(v.budget) ? v.budget : undefined;
	const num = (x: unknown) => (typeof x === "number" ? x : undefined);
	return {
		extraPermissions: perms(v.extraPermissions),
		delegationChains: chains,
		budget: b ? { limit: num(b.limit), spent: num(b.spent), cost: num(b.cost) } : undefined,
		rateUsage: num(v.rateUsage),
	};
}

/**
 * Opt-in, admin-only what-if endpoint. Mounts:
 * - POST /agents/:id/simulate
 *
 * Body, one of:
 * - { action, resource, context?, overrides? }  single decision with trace
 * - { matrix: { actions, resources }, context?, overrides? }  decisions for a grid
 * - { effective: true }  one row per rule and action the agent holds
 *
 * Nothing is written: no audit rows, no rate counters, no spend.
 */
export function simulator(config: SimulatorPluginConfig = {}): TheAuthPlugin {
	return {
		id: "theauth-simulator",

		async init(ctx): Promise<undefined> {
			const sim = createSimulator({ db: ctx.db });

			ctx.addEndpoint({
				method: "POST",
				path: "/agents/:id/simulate",
				metadata: {
					requireAuth: true,
					description:
						"Simulate what an agent would be allowed to do (admin only, no side effects)",
					rateLimit: { window: 60, max: 120 },
				},
				async handler(request, ectx) {
					const user = await ectx.getUser(request);
					if (!user) return json({ error: "login_required" }, 401);
					const admin = config.isAdmin ? await config.isAdmin(user) : false;
					if (!admin)
						return json({ error: "forbidden", error_description: "Admin access required" }, 403);

					const match = ROUTE.exec(new URL(request.url).pathname.replace(/^.*?(?=\/agents\/)/, ""));
					const agentId = match?.[1] ? decodeURIComponent(match[1]) : undefined;
					if (!agentId)
						return json({ error: "invalid_request", error_description: "Missing agent id" }, 400);

					let body: unknown;
					try {
						body = await request.json();
					} catch {
						return json({ error: "invalid_request", error_description: "Invalid JSON body" }, 400);
					}
					if (!isRecord(body)) {
						return json(
							{ error: "invalid_request", error_description: "Body must be an object" },
							400,
						);
					}

					const context = parseContext(body.context);
					const overrides = parseOverrides(body.overrides);

					if (body.effective === true) {
						const r = await sim.effectivePermissions(agentId, context);
						return r.success
							? json({ agentId, permissions: r.data })
							: json(
									{ error: r.error.code, error_description: r.error.message },
									r.error.code === "SIMULATE_AGENT_NOT_FOUND" ? 404 : 400,
								);
					}

					if (isRecord(body.matrix)) {
						const actions = strList(body.matrix.actions);
						const resources = strList(body.matrix.resources);
						if (!actions || !resources) {
							return json(
								{
									error: "invalid_request",
									error_description: "matrix needs actions and resources string arrays",
								},
								400,
							);
						}
						const r = await sim.simulateMany({
							agentIds: [agentId],
							actions,
							resources,
							context,
							overrides,
						});
						return r.success
							? json({ agentId, cells: r.data })
							: json({ error: r.error.code, error_description: r.error.message }, 400);
					}

					const action = str(body.action);
					const resource = str(body.resource);
					if (!action || !resource) {
						return json(
							{ error: "invalid_request", error_description: "action and resource are required" },
							400,
						);
					}
					const input: SimulateInput = { agentId, action, resource, context, overrides };
					const r = await sim.simulate(input);
					return r.success
						? json(r.data)
						: json({ error: r.error.code, error_description: r.error.message }, 400);
				},
			});

			return undefined;
		},
	};
}
