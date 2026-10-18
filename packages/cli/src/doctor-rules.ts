import type { DoctorCheck } from "./tools-commands.js";

/**
 * Severity of a config rule. `fail` makes `theauth doctor` exit 1. `warn` and `info` do not.
 * Maps the Go doctor's severities: critical and high become fail, medium and low become warn, info stays info.
 */
export type RuleSeverity = "info" | "warn" | "fail";

/** A doctor check raised by a config rule. `status` is `fail` for fail, `warn` otherwise. */
export interface DoctorRule extends DoctorCheck {
	severity: RuleSeverity;
}

export type RuleEnv = Record<string, string | undefined>;

/** OWASP PBKDF2-HMAC-SHA256 target used by core when no iteration count is configured. */
export const PBKDF2_TARGET_ITERATIONS = 600_000;

const MIN_SECRET_LENGTH = 32;
const MIN_PASSWORD_LENGTH = 12;
const DEFAULT_PASSWORD_LENGTH = 8;
const MAX_SESSION_TTL_SECONDS = 30 * 24 * 60 * 60;
const DEFAULT_HOOK_TIMEOUT_MS = 2000;
const PLACEHOLDER = /change[-_ ]?me|your[-_ ]?secret|secret|password|example|test|default|xxxx/i;

/**
 * The config fields the rules read, declared here rather than taken from `RuleConfig`, so the rules
 * keep type-checking against a core build that lags the source. A loaded `RuleConfig` is assignable to it.
 */
export interface RuleConfig {
	secret?: string;
	baseUrl?: string;
	trustForwardedHeaders?: boolean;
	trustedProxy?: { trustedProxyCount?: number; trustedHeader?: string };
	secondaryStorage?: unknown;
	audit?: { tamperEvident?: boolean; hmacKey?: string };
	auth?: { adapter?: unknown; session?: { secret?: string; maxAge?: number } };
	username?: { password?: { minLength?: number }; pbkdf2Iterations?: number };
	passwordReset?: { pbkdf2Iterations?: number; sendResetEmail?: unknown };
	totp?: unknown;
	passkey?: { rpId?: string };
	sso?: { saml?: unknown[]; storage?: unknown };
	mcp?: {
		enabled?: boolean;
		signingSecret?: string;
		consentPage?: string;
		jtiDenylist?: unknown;
		revocation?: { mode?: string };
		clientIdMetadataDocuments?: { enabled?: boolean; allowedHosts?: string[]; resolver?: unknown };
		registration?: { enabled?: boolean; agentForClient?: unknown };
	};
	hooks?: { beforeAuthorize?: unknown; beforeAgentCreate?: unknown };
	hookSafety?: {
		timeoutMs?: number;
		beforeAuthorize?: { timeoutMs?: number };
		beforeAgentCreate?: { timeoutMs?: number };
	};
}

type RuleFn = (config: RuleConfig, env: RuleEnv) => DoctorRule[];

function rule(id: string, severity: RuleSeverity, message: string, fix: string): DoctorRule {
	return { id, status: severity === "fail" ? "fail" : "warn", severity, message, fix };
}

function parseUrl(value: unknown): URL | null {
	if (typeof value !== "string" || value === "") return null;
	try {
		return new URL(value);
	} catch {
		return null;
	}
}

function isLocalHost(host: string): boolean {
	return (
		host === "localhost" || host === "::1" || host.endsWith(".localhost") || host.startsWith("127.")
	);
}

/** Positive integer from an env value, or undefined when unset or not a number. */
function parseEnvNumber(value: string | undefined): number | undefined {
	if (value === undefined || value.trim() === "") return undefined;
	const n = Number(value);
	return Number.isFinite(n) && n >= 0 ? n : undefined;
}

function secretRules(c: RuleConfig): DoctorRule[] {
	const candidates: Array<[string, unknown]> = [
		["secret", c.secret],
		["auth.session.secret", c.auth?.session?.secret],
		["mcp.signingSecret", c.mcp?.signingSecret],
	];
	const problems: string[] = [];
	for (const [name, value] of candidates) {
		if (typeof value !== "string") continue;
		if (value.length < MIN_SECRET_LENGTH) {
			problems.push(`${name} is ${value.length} characters, need at least ${MIN_SECRET_LENGTH}`);
		} else if (PLACEHOLDER.test(value) || new Set(value).size < 8) {
			problems.push(`${name} looks like a default or placeholder value`);
		}
	}
	if (problems.length === 0) return [];
	return [
		rule(
			"secret.weak",
			"fail",
			`Signing secret is weak: ${problems.join("; ")}`,
			"Generate a value with `theauth secret` and load it from an environment variable.",
		),
	];
}

function sessionRules(c: RuleConfig): DoctorRule[] {
	const maxAge = c.auth?.session?.maxAge;
	if (typeof maxAge !== "number" || maxAge <= MAX_SESSION_TTL_SECONDS) return [];
	return [
		rule(
			"session.ttl_long",
			"warn",
			`auth.session.maxAge is ${maxAge} seconds, over 30 days`,
			"Set auth.session.maxAge to 2592000 or less.",
		),
	];
}

function cookieRules(c: RuleConfig): DoctorRule[] {
	const url = parseUrl(c.baseUrl);
	if (url?.protocol !== "http:" || isLocalHost(url.hostname)) return [];
	return [
		rule(
			"cookie.insecure_http",
			"fail",
			`baseUrl ${url.hostname} is plain http, so browsers will not store the Secure session cookie and any traffic that arrives is cleartext`,
			"Serve the app over https and set baseUrl to the https URL.",
		),
	];
}

function proxyConfigured(proxy: RuleConfig["trustedProxy"]): boolean {
	return Boolean(proxy?.trustedHeader) || (proxy?.trustedProxyCount ?? 0) > 0;
}

function proxyRules(c: RuleConfig): DoctorRule[] {
	if (c.trustForwardedHeaders !== true || proxyConfigured(c.trustedProxy)) return [];
	return [
		rule(
			"network.trusted_proxies_empty",
			"warn",
			"trustForwardedHeaders is on but no trustedProxy is set, so any client can send X-Forwarded-Host and X-Forwarded-Proto",
			"Set trustedProxy to { trustedProxyCount } or { trustedHeader } for your edge, or turn trustForwardedHeaders off.",
		),
	];
}

function mfaRules(c: RuleConfig): DoctorRule[] {
	const humanAuth = Boolean(c.username || c.auth?.session || c.auth?.adapter);
	if (!humanAuth || c.totp || c.passkey) return [];
	return [
		rule(
			"mfa.none_enabled",
			"warn",
			"Human sign-in is configured but neither totp nor passkey is set, so accounts rely on one factor",
			"Enable totp or passkey in the config.",
		),
	];
}

function passwordRules(c: RuleConfig): DoctorRule[] {
	if (!c.username) return [];
	const min = c.username.password?.minLength ?? DEFAULT_PASSWORD_LENGTH;
	if (min >= MIN_PASSWORD_LENGTH) return [];
	return [
		rule(
			"password.min_length_low",
			"warn",
			`username.password.minLength is ${min}, below ${MIN_PASSWORD_LENGTH}`,
			`Set username.password.minLength to ${MIN_PASSWORD_LENGTH} or more.`,
		),
	];
}

function pbkdf2Rules(c: RuleConfig, env: RuleEnv): DoctorRule[] {
	const envIterations = parseEnvNumber(env.THEAUTH_PBKDF2_ITERATIONS);
	const flows: Array<{ name: string; used: boolean; value: number | undefined }> = [
		{
			name: "username.pbkdf2Iterations",
			used: c.username !== undefined,
			value: c.username?.pbkdf2Iterations,
		},
		{
			name: "passwordReset.pbkdf2Iterations",
			used: c.passwordReset !== undefined,
			value: c.passwordReset?.pbkdf2Iterations,
		},
	];
	const low = flows.flatMap((flow) => {
		if (!flow.used) return [];
		const effective = flow.value ?? envIterations ?? PBKDF2_TARGET_ITERATIONS;
		return effective < PBKDF2_TARGET_ITERATIONS ? [`${flow.name} resolves to ${effective}`] : [];
	});
	if (low.length === 0) return [];
	return [
		rule(
			"password.pbkdf2_iterations_low",
			"warn",
			`PBKDF2 iterations are below ${PBKDF2_TARGET_ITERATIONS}: ${low.join("; ")}`,
			"Remove the override, or set it to 600000 or more (and THEAUTH_PBKDF2_ITERATIONS likewise).",
		),
	];
}

function passkeyRules(c: RuleConfig): DoctorRule[] {
	const url = parseUrl(c.baseUrl);
	if (!c.passkey || !url || typeof c.passkey.rpId !== "string") return [];
	const host = url.hostname.toLowerCase();
	const rpId = c.passkey.rpId.toLowerCase();
	if (host === rpId || host.endsWith(`.${rpId}`)) return [];
	return [
		rule(
			"webauthn.rpid_mismatch",
			"fail",
			`passkey.rpId ${rpId} is not the baseUrl host ${host} or a parent domain of it, so passkey sign-in will fail`,
			"Set passkey.rpId to the baseUrl host or its registrable parent.",
		),
	];
}

function samlRules(c: RuleConfig): DoctorRule[] {
	const samlProviders = c.sso?.saml?.length ?? 0;
	if (samlProviders === 0 || c.sso?.storage || c.secondaryStorage) return [];
	return [
		rule(
			"saml.tracker_in_memory",
			"warn",
			"SAML request and assertion ids are tracked in process memory, so replay protection does not span replicas",
			"Set secondaryStorage when running several replicas. Ignore this on a single instance.",
		),
	];
}

function mcpRules(c: RuleConfig, env: RuleEnv): DoctorRule[] {
	const mcp = c.mcp;
	if (!mcp?.enabled) return [];
	const out: DoctorRule[] = [];
	const mode = mcp.revocation?.mode ?? env.THEAUTH_MCP_REVOCATION_MODE;
	if (mode === "offline" && !mcp.jtiDenylist) {
		out.push(
			rule(
				"mcp.offline_no_jti_denylist",
				"warn",
				"MCP revocation is offline and no jtiDenylist is set, so revoked access tokens stay valid until they expire",
				"Set mcp.jtiDenylist, or use the live or cached revocation mode.",
			),
		);
	}
	const cimd = mcp.clientIdMetadataDocuments;
	if (cimd?.enabled && (cimd.allowedHosts?.length ?? 0) === 0 && cimd.resolver === undefined) {
		out.push(
			rule(
				"cimd.no_host_allowlist",
				"warn",
				"clientIdMetadataDocuments is enabled with no allowedHosts and no resolver, so any public host can serve client metadata",
				"Set clientIdMetadataDocuments.allowedHosts to the hosts you trust, or a resolver such as createDohResolver().",
			),
		);
	}
	if (!mcp.consentPage) {
		out.push(
			rule(
				"mcp.consent_page_missing",
				"warn",
				"No mcp.consentPage is set, so authorization codes are issued without a consent screen",
				"Set mcp.consentPage to a page where the user approves each client.",
			),
		);
	}
	if (mcp.registration?.enabled !== false && !mcp.registration?.agentForClient) {
		out.push(
			rule(
				"mcp.registration_open",
				"warn",
				"Dynamic client registration is open and new clients are not bound to an agent",
				"Set mcp.registration.agentForClient to bind new clients, or set registration.enabled to false.",
			),
		);
	}
	return out;
}

function hookRules(c: RuleConfig, env: RuleEnv): DoctorRule[] {
	const hooks = c.hooks;
	if (!hooks) return [];
	const envTimeout = parseEnvNumber(env.THEAUTH_HOOK_TIMEOUT_MS);
	const names = (["beforeAuthorize", "beforeAgentCreate"] as const).filter((name) => {
		if (!hooks[name]) return false;
		const timeout =
			c.hookSafety?.[name]?.timeoutMs ??
			c.hookSafety?.timeoutMs ??
			envTimeout ??
			DEFAULT_HOOK_TIMEOUT_MS;
		return timeout === 0;
	});
	if (names.length === 0) return [];
	return [
		rule(
			"hooks.timeout_disabled",
			"warn",
			`${names.join(" and ")} run with timeoutMs 0, so a hung hook blocks the request forever`,
			"Set hookSafety.timeoutMs to a value such as 2000.",
		),
	];
}

function auditRules(c: RuleConfig): DoctorRule[] {
	if (c.audit?.tamperEvident !== true) {
		return [
			rule(
				"audit.tamper_evident_off",
				"info",
				"Audit rows are not hash-chained, so edits to the audit table are not detectable",
				"Set audit.tamperEvident to true and audit.hmacKey to a secret.",
			),
		];
	}
	if (c.audit.hmacKey) return [];
	return [
		rule(
			"audit.hmac_key_missing",
			"warn",
			"audit.tamperEvident is on without audit.hmacKey, so anyone with database write access can recompute the chain",
			"Set audit.hmacKey to a secret kept outside the database.",
		),
	];
}

const RULES: RuleFn[] = [
	(c) => secretRules(c),
	(c) => sessionRules(c),
	(c) => cookieRules(c),
	(c) => proxyRules(c),
	(c) => mfaRules(c),
	(c) => passwordRules(c),
	pbkdf2Rules,
	(c) => passkeyRules(c),
	(c) => samlRules(c),
	mcpRules,
	hookRules,
	(c) => auditRules(c),
];

/**
 * Evaluates the config rules against a loaded `theauth.config`. Rules appear only when they fire,
 * so a clean config yields no entries. Returns nothing when no config could be loaded.
 */
export function configRules(config: RuleConfig | null, env: RuleEnv): DoctorRule[] {
	if (!config) return [];
	return RULES.flatMap((run) => run(config, env));
}
