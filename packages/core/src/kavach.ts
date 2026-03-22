import { randomUUID } from "node:crypto";
import { eq } from "drizzle-orm";
import { createAgentModule } from "./agent/agent.js";
import { createAnomalyDetector } from "./anomaly/detector.js";
import { createAuditModule } from "./audit/audit.js";
import { generateComplianceReport } from "./compliance/report.js";
import type { ComplianceReportOptions } from "./compliance/report.js";
import type { ResolvedUser } from "./auth/types.js";
import { createDatabase } from "./db/database.js";
import { createTables } from "./db/migrations.js";
import { mcpServers } from "./db/schema.js";
import { createDelegationModule } from "./delegation/delegation.js";
import { createPermissionEngine } from "./permission/engine.js";
import type { SessionManager } from "./session/session.js";
import { createSessionManager } from "./session/session.js";
import type {
	AuditExportOptions,
	AuditFilter,
	AuthorizeContext,
	AuthorizeRequest,
	AuthorizeResult,
	CostFilter,
	DelegateInput,
	DelegationChain,
	KavachConfig,
	McpServer,
	McpServerInput,
	RequestContext,
} from "./types.js";

/**
 * Create a KavachOS instance.
 *
 * The factory is **async** so it can open database connections for Postgres
 * and MySQL (which require async driver initialisation) and optionally run
 * `CREATE TABLE IF NOT EXISTS` for all schema tables.
 *
 * @example SQLite (simplest)
 * ```typescript
 * import { createKavach } from 'kavachos';
 *
 * const kavach = await createKavach({
 *   database: { provider: 'sqlite', url: 'kavach.db' },
 * });
 * ```
 *
 * @example Postgres
 * ```typescript
 * const kavach = await createKavach({
 *   database: { provider: 'postgres', url: process.env.DATABASE_URL },
 * });
 * ```
 *
 * @example MySQL – skip auto-migration (tables managed externally)
 * ```typescript
 * const kavach = await createKavach({
 *   database: {
 *     provider: 'mysql',
 *     url: process.env.DATABASE_URL,
 *     skipMigrations: true,
 *   },
 * });
 * ```
 */
export async function createKavach(config: KavachConfig) {
	const authAdapter = config.auth?.adapter ?? null;

	const db = await createDatabase(config.database);

	// Automatically create tables unless the caller has opted out.
	// Uses CREATE TABLE IF NOT EXISTS so it is safe to run every startup.
	if (!config.database.skipMigrations) {
		await createTables(db, config.database.provider);
	}

	const agentConfig = {
		db,
		maxPerUser: config.agents?.maxPerUser ?? 10,
		defaultPermissions: config.agents?.defaultPermissions ?? [],
		tokenExpiry: config.agents?.tokenExpiry ?? "24h",
	};

	const agentModule = createAgentModule(agentConfig);

	const permissionEngine = createPermissionEngine({
		db,
		auditAll: config.agents?.auditAll ?? true,
	});

	const auditModule = createAuditModule({ db });

	const delegationModule = createDelegationModule({ db });

	// Session manager – only created when the caller opts in via auth.session.
	const sessionManager: SessionManager | null = config.auth?.session
		? createSessionManager(config.auth.session, db)
		: null;

	const anomalyDetector = createAnomalyDetector(config.anomaly ?? {}, db);

	// Authorize: look up agent, check own permissions then delegated permissions
	async function authorize(
		agentId: string,
		request: AuthorizeRequest,
		context?: AuthorizeContext,
	): Promise<AuthorizeResult> {
		const agent = await agentModule.get(agentId);
		if (!agent) {
			return {
				allowed: false,
				reason: `Agent "${agentId}" not found`,
				auditId: "",
			};
		}
		if (agent.status !== "active") {
			return {
				allowed: false,
				reason: `Agent "${agent.name}" is ${agent.status}`,
				auditId: "",
			};
		}

		// Build RequestContext (ip + userAgent) from the broader AuthorizeContext
		const requestContext: RequestContext | undefined =
			context && (context.ip !== undefined || context.userAgent !== undefined)
				? { ip: context.ip, userAgent: context.userAgent }
				: undefined;

		const enrichedRequest: AuthorizeRequest = requestContext
			? { ...request, context: requestContext }
			: request;

		// First check the agent's own permissions
		const ownResult = await permissionEngine.authorize(agent, enrichedRequest, context?.tokensCost);
		if (ownResult.allowed) return ownResult;

		// If own permissions deny, check effective permissions from delegation chains
		const delegatedPerms = await delegationModule.getEffectivePermissions(agentId);
		if (delegatedPerms.length === 0) return ownResult;

		// Build a synthetic agent view with delegated permissions merged in
		const agentWithDelegated = { ...agent, permissions: delegatedPerms };
		const delegatedResult = await permissionEngine.authorize(
			agentWithDelegated,
			enrichedRequest,
			context?.tokensCost,
		);
		if (delegatedResult.allowed) return delegatedResult;

		// Both denied — return the original denial so the message references the agent by name
		return ownResult;
	}

	// Authorize by token: validate token then check permissions
	async function authorizeByToken(
		token: string,
		request: AuthorizeRequest,
		context?: AuthorizeContext,
	): Promise<AuthorizeResult> {
		const agent = await agentModule.validateToken(token);
		if (!agent) {
			return {
				allowed: false,
				reason: "Invalid or expired agent token",
				auditId: "",
			};
		}

		// Build RequestContext (ip + userAgent) from the broader AuthorizeContext
		const requestContext: RequestContext | undefined =
			context && (context.ip !== undefined || context.userAgent !== undefined)
				? { ip: context.ip, userAgent: context.userAgent }
				: undefined;

		const enrichedRequest: AuthorizeRequest = requestContext
			? { ...request, context: requestContext }
			: request;

		return permissionEngine.authorize(agent, enrichedRequest, context?.tokensCost);
	}

	// Delegate: verify parent permissions then create chain
	async function delegate(input: DelegateInput): Promise<DelegationChain> {
		const parentAgent = await agentModule.get(input.fromAgent);
		if (!parentAgent) throw new Error(`Parent agent "${input.fromAgent}" not found`);
		if (parentAgent.status !== "active") {
			throw new Error(`Parent agent "${parentAgent.name}" is ${parentAgent.status}`);
		}
		return delegationModule.delegate(input, parentAgent.permissions);
	}

	// ── MCP server registry ─────────────────────────────────────────
	// Uses the kavach_mcp_servers table (defined in db/schema.ts).
	const mcpRegistry = {
		/**
		 * Register a new MCP tool server.
		 *
		 * Persists the server entry to the `kavach_mcp_servers` table.
		 * The returned record includes the generated `id` and `createdAt`.
		 */
		async register(input: McpServerInput): Promise<McpServer> {
			const now = new Date();
			const id = randomUUID();

			await db.insert(mcpServers).values({
				id,
				name: input.name,
				endpoint: input.endpoint,
				tools: input.tools,
				authRequired: input.authRequired ?? true,
				rateLimitRpm: input.rateLimit?.rpm ?? null,
				status: "active",
				createdAt: now,
				updatedAt: now,
			});

			return {
				id,
				name: input.name,
				endpoint: input.endpoint,
				tools: input.tools,
				authRequired: input.authRequired ?? true,
				createdAt: now,
			};
		},

		/**
		 * List all registered MCP servers (active and inactive).
		 */
		async list(): Promise<McpServer[]> {
			const rows = await db.select().from(mcpServers);
			return rows.map((row) => ({
				id: row.id,
				name: row.name,
				endpoint: row.endpoint,
				tools: row.tools,
				authRequired: row.authRequired,
				createdAt: row.createdAt,
			}));
		},

		/**
		 * Get a single MCP server by ID. Returns null when not found.
		 */
		async get(id: string): Promise<McpServer | null> {
			const rows = await db.select().from(mcpServers).where(eq(mcpServers.id, id));
			const row = rows[0];
			if (!row) return null;
			return {
				id: row.id,
				name: row.name,
				endpoint: row.endpoint,
				tools: row.tools,
				authRequired: row.authRequired,
				createdAt: row.createdAt,
			};
		},
	};

	return {
		agent: {
			create: agentModule.create,
			get: agentModule.get,
			list: agentModule.list,
			update: agentModule.update,
			revoke: agentModule.revoke,
			rotate: agentModule.rotate,
			validateToken: agentModule.validateToken,
		},
		authorize,
		authorizeByToken,
		delegate,
		delegation: {
			revoke: delegationModule.revokeDelegation,
			getEffectivePermissions: delegationModule.getEffectivePermissions,
			listChains: delegationModule.listChains,
		},
		audit: {
			query: (filter: AuditFilter) => auditModule.query(filter),
			export: (options: AuditExportOptions) => auditModule.export(options),
			cleanup: (options: { retentionDays: number }) => auditModule.cleanup(options),
			getCostSummary: (filter?: CostFilter) => auditModule.getCostSummary(filter),
		},
		/**
		 * MCP server registration.
		 *
		 * Register and look up MCP tool servers. Uses the `kavach_mcp_servers`
		 * database table — no separate in-memory store needed.
		 */
		mcp: mcpRegistry,
		/**
		 * Compliance report generation.
		 *
		 * Generate framework-specific compliance reports (EU AI Act, NIST AI RMF,
		 * SOC 2, ISO 42001) backed by live agent and audit data.
		 */
		compliance: {
			generateReport: (options: ComplianceReportOptions) =>
				generateComplianceReport(db, options),
		},
		/**
		 * Behavioural anomaly detection.
		 *
		 * Scan recent audit logs for unusual patterns — high call frequency,
		 * elevated denial rates, off-hours access, new resource patterns, and
		 * privilege escalation attempts.
		 */
		anomaly: {
			scan: anomalyDetector.scan,
			getSummary: anomalyDetector.getSummary,
		},
		/**
		 * Human auth integration.
		 *
		 * `resolveUser` extracts the authenticated human from an inbound HTTP
		 * request via the configured adapter.  `session` is a full session
		 * manager (create / validate / revoke) when `auth.session` was passed
		 * to `createKavach()`.
		 *
		 * @example
		 * ```typescript
		 * app.use(async (req, res, next) => {
		 *   const user = await kavach.auth.resolveUser(req);
		 *   if (!user) return res.status(401).json({ error: 'Unauthorized' });
		 *   req.user = user;
		 *   next();
		 * });
		 * ```
		 */
		auth: {
			async resolveUser(request: Request): Promise<ResolvedUser | null> {
				if (!authAdapter) return null;
				return authAdapter.resolveUser(request);
			},
			session: sessionManager,
		},
		/**
		 * Resolve a human user from an incoming HTTP request.
		 *
		 * @deprecated Use `kavach.auth.resolveUser(request)` instead.
		 */
		async resolveUser(request: Request): Promise<ResolvedUser | null> {
			if (!authAdapter) return null;
			return authAdapter.resolveUser(request);
		},
		/** Direct database access for advanced usage */
		db,
	};
}

export type Kavach = Awaited<ReturnType<typeof createKavach>>;
