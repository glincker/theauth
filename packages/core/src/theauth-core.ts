import { createAgentModule } from "./agent/agent.js";
import { createAgentFacade } from "./agent/facade.js";
import { createPrivilegeAnalyzer } from "./analyzer/privilege.js";
import { createApprovalModule } from "./approval/approval.js";
import { createAuditFacade } from "./audit/facade.js";
import { createConfiguredAuditModule } from "./audit/setup.js";
import { createHumanAuthModules } from "./auth/human-modules.js";
import type { SignInGate } from "./auth/sign-in-gate.js";
import { createSignInGate } from "./auth/sign-in-gate.js";
import type { ResolvedUser } from "./auth/types.js";
import { createAuthorizePipeline } from "./authorize/pipeline.js";
import type { Database } from "./db/database.js";
import { createSchemaApi, ensureSchema } from "./db/migrations.js";
import { createDelegationModule } from "./delegation/delegation.js";
import { createDidModule } from "./did/module.js";
import { createExplainer } from "./explain/explain.js";
import { createHookRuntime } from "./hooks/runtime.js";
import { createCoreRevocationBus, withMcpSignOutRevocation } from "./mcp/revocation-wiring.js";
import { createMcpServerRegistry } from "./mcp/server-registry.js";
import { createObservability } from "./observability/index.js";
import { createPermissionEngine } from "./permission/engine.js";
import {
	createEndpointContext,
	createRequestHookRunner,
	registerSessionEndpoints,
	withSignInGatePlugin,
} from "./plugin/core-wiring.js";
import { createPluginRouter } from "./plugin/router.js";
import { initializePlugins } from "./plugin/runner.js";
import { createPolicyModule } from "./policies/budget.js";
import { createPolicyEngine } from "./policy/engine.js";
import type { PolicyEngine } from "./policy/types.js";
import type { RedirectChainManager } from "./redirect/chain.js";
import { createRedirectChain } from "./redirect/chain.js";
import type { SessionFreshnessModule } from "./session/freshness.js";
import { createSessionFreshnessModule } from "./session/freshness.js";
import type { SessionManager } from "./session/session.js";
import { createSessionManager } from "./session/session.js";
import { assertSecondaryStorageConfig, createSecondaryStorageResolver } from "./storage/resolve.js";
import { createTenantModule } from "./tenant/tenant.js";
import { createTrustModule } from "./trust/scoring.js";
import type { TheAuthConfig } from "./types.js";
import { createUserModule } from "./user/user.js";

/** Opens the database for a config. Injected so entry points choose which drivers can load. */
export type DatabaseOpener = (config: TheAuthConfig["database"]) => Promise<Database>;

export async function createTheAuthWith(config: TheAuthConfig, openDatabase: DatabaseOpener) {
	const authAdapter = config.auth?.adapter ?? null;

	const db = await openDatabase(config.database);

	// Migrates, or with skipMigrations throws SchemaOutdatedError when the schema is behind.
	await ensureSchema(db, config);

	// The policy engine can open approval requests, so the approval module is created first.
	const hooks = config.hooks ?? {};
	const { runBeforeAuthorize, guardAgentCreate } = createHookRuntime(hooks, config.hookSafety);
	const observability = createObservability(config.observability, config.logger);
	const approvalModule = createApprovalModule(config.approval ?? {}, db, {
		observability,
		// The webhook module is built further down, so it is looked up when a request opens.
		webhooks: () => webhookModule,
	});
	const policyEngine: PolicyEngine = createPolicyEngine({
		db,
		config: config.policy,
		approval: approvalModule,
		observability,
		runBeforeAuthorize: hooks.beforeAuthorize ? runBeforeAuthorize : undefined,
	});

	const revocations = createCoreRevocationBus(db, config, observability.logger);
	const agentModule = createAgentModule({
		revocations,
		db,
		maxPerUser: config.agents?.maxPerUser ?? 10,
		defaultPermissions: config.agents?.defaultPermissions ?? [],
		tokenExpiry: config.agents?.tokenExpiry ?? "24h",
	});
	const userModule = createUserModule({ db });
	const permissionEngine = createPermissionEngine({
		db,
		auditAll: config.agents?.auditAll ?? true,
	});

	const auditModule = createConfiguredAuditModule(db, config.audit);

	const delegationModule = createDelegationModule({ db, revocations });
	const sessionManager: SessionManager | null = withMcpSignOutRevocation(
		config.auth?.session ? createSessionManager(config.auth.session, db) : null,
		revocations,
		config,
	);

	// Always created. Without config, only the forced password change is active.
	// It reads only tables whose feature is enabled, mirroring createTables feature detection.
	const signInGate: SignInGate = createSignInGate({
		db,
		config: config.signInGate,
		sessionSecret: config.auth?.session?.secret,
		totpAvailable: !!config.totp || (config.plugins?.some((p) => p.id === "theauth-2fa") ?? false),
		usernameAccountsAvailable: !!config.username,
	});

	const privilegeAnalyzer = createPrivilegeAnalyzer(db);
	const { authorize, authorizeByToken } = createAuthorizePipeline({
		db,
		hooks,
		runBeforeAuthorize,
		observability,
		agentModule,
		permissionEngine,
		delegationModule,
	});
	const { explain } = createExplainer({
		db,
		agentModule,
		runBeforeAuthorize,
		hookConfigured: !!hooks.beforeAuthorize,
	});

	const tenantModule = createTenantModule(db);
	const policyModule = createPolicyModule(db);
	const trustModule = createTrustModule({}, db);
	const didModule = createDidModule(db, config.did);
	const {
		magicLinkModule,
		emailOtpModule,
		totpModule,
		passkeyModule,
		orgModule,
		ssoModule,
		adminModule,
		apiKeyManagerModule,
		usernameModule,
		oneTimeTokenModule,
		passwordResetModule,
		emailVerificationModule,
		phoneModule,
		captchaModule,
		webhookModule,
	} = createHumanAuthModules(config, db, sessionManager, signInGate, revocations);

	const redirectChain: RedirectChainManager = createRedirectChain(config.redirects);
	// Runs after core modules so plugins can depend on them.
	assertSecondaryStorageConfig(config.secondaryStorage);
	const secondaryStorage = createSecondaryStorageResolver(config.secondaryStorage, db);
	const pluginRegistry = await initializePlugins(
		withSignInGatePlugin(config.plugins ?? [], sessionManager !== null),
		db,
		config,
		sessionManager,
		secondaryStorage,
		signInGate,
		revocations,
	);

	const endpointCtx = createEndpointContext(db, config, sessionManager);
	const runRequestHooks = createRequestHookRunner(pluginRegistry);
	const pluginRouter = createPluginRouter(pluginRegistry.endpoints, {
		trustedProxy: config.trustedProxy,
	});

	if (sessionManager) registerSessionEndpoints(pluginRegistry, sessionManager, endpointCtx);

	const {
		agent: agentProxy,
		delegate,
		delegation,
	} = createAgentFacade({
		agentModule,
		delegationModule,
		hooks,
		guardAgentCreate,
		pluginContext: pluginRegistry.pluginContext,
	});

	return {
		agent: agentProxy,
		/** User rows: idempotent `create({ email, name?, id? })` and `get(idOrEmail)`. */
		user: userModule,
		authorize,
		authorizeByToken,
		/** Read-only account of what `authorize()` would decide and why. No audit rows, no counters. */
		explain,
		/** Logger and decision event counters: `stats()` reports emitted, errors and slow listener calls. */
		observability: { logger: observability.logger, stats: observability.stats },
		delegate,
		delegation,
		audit: createAuditFacade(auditModule),
		/** MCP server registration, backed by the `theauth_mcp_servers` table. */
		mcp: createMcpServerRegistry(db),
		/** @internal Revocation bus: `createMcpModule({ auth })` subscribes its freshness cache to it. */
		revocations,
		/** Schema migration ledger: `schema.status()` lists applied and pending migrations. */
		schema: createSchemaApi(db, config),
		/** Per-feature secondary storage (rate limits, device codes, ...). */
		secondaryStorage,
		/** Least-privilege analyzer: compares granted permissions against audit log usage. */
		analyzer: {
			analyzeAgent: privilegeAnalyzer.analyzeAgent,
			analyzeAll: privilegeAnalyzer.analyzeAll,
			getSummary: privilegeAnalyzer.getSummary,
		},
		/**
		 * ```typescript
		 * app.use(async (req, res, next) => {
		 *   const user = await theauth.auth.resolveUser(req);
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
		/** @deprecated Use `theauth.auth.resolveUser(request)` instead. */
		async resolveUser(request: Request): Promise<ResolvedUser | null> {
			if (!authAdapter) return null;
			return authAdapter.resolveUser(request);
		},
		db,
		/** Multi-tenant isolation: tenants (organizations) share one instance with isolated data. */
		tenant: tenantModule,
		/** Per-agent, per-user or per-tenant spending caps. Exceeded policies warn, throttle, block or revoke. */
		policies: policyModule,
		/** Async human approval flows (CIBA-style): create requests, notify humans, approve or deny. */
		approval: approvalModule,
		/** Graduated autonomy trust scores (0-100) derived from audit history. */
		trust: trustModule,
		/**
		 * W3C Decentralized Identifiers for agents. Private keys are returned on generation and never stored.
		 *
		 * @example
		 * ```typescript
		 * const { agentDid, privateKeyJwk } = await theauth.did.generateKey(agentId);
		 * const signed = await theauth.did.sign(agentId, { action: 'read' }, privateKeyJwk);
		 * const result = await theauth.did.verify(signed.jws, agentDid.did);
		 * ```
		 */
		did: didModule,
		/**
		 * Magic link authentication. Null unless `magicLink` and `auth.session` are configured.
		 *
		 * @example
		 * ```typescript
		 * // In your route handler
		 * const response = await theauth.magicLink?.handleRequest(request);
		 * if (response) return response;
		 * ```
		 */
		magicLink: magicLinkModule,
		/**
		 * Email OTP authentication. Null unless `emailOtp` and `auth.session` are configured.
		 *
		 * @example
		 * ```typescript
		 * const response = await theauth.emailOtp?.handleRequest(request);
		 * if (response) return response;
		 * ```
		 */
		emailOtp: emailOtpModule,
		/**
		 * TOTP two-factor authentication. Null unless `totp` is configured.
		 *
		 * @example
		 * ```typescript
		 * // On setup (show QR code to user)
		 * const { secret, uri, backupCodes } = await theauth.totp.setup(userId);
		 *
		 * // After user scans QR and enters code
		 * const { enabled } = await theauth.totp.enable(userId, totpCode);
		 *
		 * // On login (after password check)
		 * const { valid } = await theauth.totp.verify(userId, totpCode);
		 * ```
		 */
		totp: totpModule,
		/**
		 * Passkey (WebAuthn) authentication. Null unless `passkey` is configured.
		 *
		 * @example
		 * ```typescript
		 * // Registration, step 1: get options, send to browser
		 * const options = await theauth.passkey.getRegistrationOptions(userId, userName);
		 *
		 * // Registration, step 2: verify browser response
		 * const { credential } = await theauth.passkey.verifyRegistration(userId, response);
		 *
		 * // Authentication, step 1: get options
		 * const options = await theauth.passkey.getAuthenticationOptions(userId);
		 *
		 * // Authentication, step 2: verify browser response
		 * const result = await theauth.passkey.verifyAuthentication(response);
		 * if (result) console.log('Authenticated user:', result.userId);
		 * ```
		 */
		passkey: passkeyModule,
		/**
		 * Organizations and RBAC. Null unless `org` is configured.
		 *
		 * @example
		 * ```typescript
		 * const org = await theauth.org?.create({ name: 'Acme', slug: 'acme', ownerId: userId });
		 * const allowed = await theauth.org?.hasPermission(org.id, userId, 'agents:create');
		 * ```
		 */
		org: orgModule,
		/**
		 * SSO (SAML 2.0 and OIDC) enterprise authentication. Null unless `sso` is configured.
		 *
		 * @example
		 * ```typescript
		 * const conn = await theauth.sso?.createConnection({ orgId, providerId: 'okta', type: 'saml', domain: 'acme.com' });
		 * const url = await theauth.sso?.getSamlAuthUrl(conn.id);
		 * ```
		 */
		sso: ssoModule,
		/**
		 * Admin module. Null unless `admin` is configured.
		 *
		 * @example
		 * ```typescript
		 * await theauth.admin?.banUser(userId, 'Spam');
		 * const { session } = await theauth.admin?.impersonate(adminId, userId);
		 * ```
		 */
		admin: adminModule,
		/**
		 * API key management. Null unless `apiKeys` is configured.
		 *
		 * @example
		 * ```typescript
		 * const { key, apiKey } = await theauth.apiKeys?.create({ userId, name: 'CI', permissions: ['agents:read'] });
		 * const result = await theauth.apiKeys?.validate(key);
		 * ```
		 */
		apiKeys: apiKeyManagerModule,
		/**
		 * Username and password authentication. Null unless `username` and `auth.session` are configured.
		 *
		 * @example
		 * ```typescript
		 * const response = await theauth.username?.handleRequest(request);
		 * if (response) return response;
		 * ```
		 */
		username: usernameModule,
		/**
		 * Password reset. Null unless `passwordReset` and `auth.session` are configured.
		 *
		 * @example
		 * ```typescript
		 * // In your route handler
		 * const response = await theauth.passwordReset?.handleRequest(request);
		 * if (response) return response;
		 *
		 * // Or programmatically
		 * await theauth.passwordReset?.requestReset('alice@example.com');
		 * await theauth.passwordReset?.resetPassword(token, 'new-password');
		 * ```
		 */
		passwordReset: passwordResetModule,
		/**
		 * Email address verification. Null unless `emailVerification` is configured.
		 *
		 * @example
		 * ```typescript
		 * // Send a verification email after sign-up
		 * await theauth.emailVerification?.sendVerification(userId, email);
		 *
		 * // Confirm from the link in the email
		 * const result = await theauth.emailVerification?.verify(token);
		 *
		 * // Check status
		 * const verified = await theauth.emailVerification?.isVerified(userId);
		 * ```
		 */
		emailVerification: emailVerificationModule,
		/** One-time tokens for email verification, password reset, invitations and custom flows. */
		oneTimeTokens: oneTimeTokenModule,
		/**
		 * Session freshness guard for sensitive operations that need a recent login, not an auto-refreshed session.
		 *
		 * @example
		 * ```typescript
		 * const stale = theauth.sessionFreshness.guard(session);
		 * if (stale) return stale; // 403 SESSION_NOT_FRESH
		 * ```
		 */
		sessionFreshness: createSessionFreshnessModule(
			config.sessionFreshness,
		) as SessionFreshnessModule,
		/**
		 * Phone (SMS OTP) authentication. Null unless `phone` and `auth.session` are configured.
		 *
		 * @example
		 * ```typescript
		 * const response = await theauth.phone?.handleRequest(request);
		 * if (response) return response;
		 * ```
		 */
		phone: phoneModule,
		/**
		 * Captcha (reCAPTCHA, hCaptcha, Turnstile). Null unless `captcha` is configured.
		 *
		 * @example
		 * ```typescript
		 * const result = await theauth.captcha?.verify(token, ip);
		 * if (!result?.success) return new Response('Captcha failed', { status: 403 });
		 * ```
		 */
		captcha: captchaModule,
		/**
		 * Webhooks. Null unless `webhooks` has at least one entry.
		 *
		 * @example
		 * ```typescript
		 * theauth.webhooks?.emit('user.created', { userId: user.id });
		 * ```
		 */
		webhooks: webhookModule,
		/**
		 * Redirect chain for returning users to their original destination after auth steps. Cookie-based.
		 *
		 * @example
		 * ```typescript
		 * // In auth middleware, save where the user was going
		 * const setCookie = theauth.redirects.capture(request);
		 * return new Response(null, { status: 302, headers: { Location: '/sign-in', 'Set-Cookie': setCookie } });
		 *
		 * // After sign-in, send user to their original destination
		 * const { url, clearCookie } = theauth.redirects.pop(request);
		 * const headers: Record<string, string> = { Location: url };
		 * if (clearCookie) headers['Set-Cookie'] = clearCookie;
		 * return new Response(null, { status: 302, headers });
		 * ```
		 */
		redirects: redirectChain,
		/**
		 * Unified policy engine (RBAC, ABAC and ReBAC) with a process-local LRU cache and deterministic invalidation.
		 *
		 * @example
		 * ```typescript
		 * const decision = await theauth.policy.evaluate({
		 *   subject: { agentId: 'agent-abc' },
		 *   action: 'read',
		 *   resource: 'tool:github:list_issues',
		 * });
		 * if (!decision.allowed) throw new Error(decision.reason);
		 *
		 * // Flush cached decisions after a permission change
		 * theauth.policy.invalidate({ agentId: 'agent-abc' });
		 *
		 * // Inspect cache health
		 * const { hits, misses, size, evictions } = theauth.policy.stats();
		 * ```
		 */
		policy: {
			evaluate: policyEngine.evaluate,
			invalidate: policyEngine.invalidate,
			stats: policyEngine.stats,
		},
		/**
		 * Plugin system: route requests through plugin endpoints and read plugin context.
		 *
		 * @example
		 * ```typescript
		 * // In a framework adapter
		 * app.all('/theauth/*', async (req) => {
		 *   const response = await theauth.plugins.handleRequest(req);
		 *   if (response) return response;
		 *   return new Response('Not Found', { status: 404 });
		 * });
		 * ```
		 */
		plugins: {
			/** Route a request through plugin endpoints. Returns null if no plugin handles it. */
			async handleRequest(request: Request, basePath = ""): Promise<Response | null> {
				const hooked = await runRequestHooks(request);
				if (hooked instanceof Response) return hooked;
				return pluginRouter.handle(hooked, basePath, endpointCtx);
			},
			/** Runs plugin `onRequest` hooks for requests TheAuth does not route itself, such as `/mcp/token`. */
			runRequestHooks,
			getEndpoints() {
				return pluginRouter.getEndpoints();
			},
			getContext(): Record<string, unknown> {
				return { ...pluginRegistry.pluginContext };
			},
			registry: pluginRegistry,
		},
	};
}

export type TheAuth = Awaited<ReturnType<typeof createTheAuthWith>>;
