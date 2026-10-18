/**
 * `theauth doctor --security`: a linter for the security settings of a theauth config.
 * It reads a loaded config object, never a database or a network, and reports stable finding ids.
 */

export type SecuritySeverity = "high" | "medium" | "low";

export const SECURITY_SEVERITY_RANK: Record<SecuritySeverity, number> = {
	low: 1,
	medium: 2,
	high: 3,
};

export interface SecurityFinding {
	/** Stable id, for example `sec.session.secret_weak`. Never renamed once released. */
	id: string;
	severity: SecuritySeverity;
	message: string;
	/** One line fix. */
	fix: string;
	/** Docs path with the anchor of this finding. */
	docs: string;
}

export type SecurityEnv = Record<string, string | undefined>;

/**
 * The fields of `TheAuthConfig` the linter reads, under their real names. A loaded `TheAuthConfig` is
 * assignable to it (the tests check that). Settings that live outside the config object, such as the
 * `createTheAuthHandler` options (cors, rate limit), the cookie flags of the session cookie and the
 * options closed over by a plugin factory, cannot be read here and are not linted.
 */
export interface SecurityConfig {
	secret?: string;
	baseUrl?: string;
	/** Hosts the deployment may answer on. Entries follow the base URL resolver pattern syntax. */
	allowedHosts?: string[];
	auth?: { session?: { secret?: string; cookieName?: string } };
	username?: { pbkdf2Iterations?: number; lockout?: unknown };
	passwordReset?: { pbkdf2Iterations?: number };
	magicLink?: unknown;
	emailOtp?: unknown;
	phone?: unknown;
	/** The only cookie flags `TheAuthConfig` carries are the redirect chain cookie ones. */
	redirects?: {
		allowedOrigins?: string[];
		cookie?: { secure?: boolean; sameSite?: string };
	};
	mcp?: { enabled?: boolean; signingSecret?: string; revocation?: { mode?: string } };
	plugins?: Array<{ id: string }>;
	/** `trustedServerUse` is the fail-open opt out of the org handler. */
	org?: { trustedServerUse?: boolean };
	/** `trustedServerUse` is the fail-open opt out of the API key handler. */
	apiKeys?: { trustedServerUse?: boolean };
}

export const PBKDF2_MIN_ITERATIONS = 600_000;
const DEFAULT_SESSION_COOKIE = "theauth_session";
const RATE_LIMIT_PLUGIN_ID = "theauth-rate-limit";
const MIN_SECRET_LENGTH = 32;
const PLACEHOLDER = /change[-_ ]?me|your[-_ ]?secret|secret|password|example|test|default|xxxx/i;

function finding(
	id: string,
	severity: SecuritySeverity,
	message: string,
	fix: string,
): SecurityFinding {
	return { id, severity, message, fix, docs: `/security-doctor#${id.replace(/[._]/g, "-")}` };
}

function isLocal(baseUrl: string | undefined): boolean {
	if (!baseUrl) return false;
	try {
		const host = new URL(baseUrl).hostname;
		return host === "localhost" || host === "::1" || host === "[::1]" || host.startsWith("127.");
	} catch {
		return false;
	}
}

function secretFindings(c: SecurityConfig, env: SecurityEnv): SecurityFinding[] {
	const candidates: Array<[string, string | undefined]> = [
		["secret", c.secret ?? env.THEAUTH_SECRET],
		["auth.session.secret", c.auth?.session?.secret],
		["mcp.signingSecret", c.mcp?.signingSecret],
	];
	const problems: string[] = [];
	for (const [name, value] of candidates) {
		if (typeof value !== "string") continue;
		if (value.length < MIN_SECRET_LENGTH) {
			problems.push(`${name} is ${value.length} characters, need ${MIN_SECRET_LENGTH}`);
		} else if (PLACEHOLDER.test(value) || new Set(value).size < 8) {
			problems.push(`${name} looks like a default or placeholder`);
		}
	}
	if (problems.length === 0) return [];
	return [
		finding(
			"sec.session.secret_weak",
			"high",
			`Session secret is weak: ${problems.join("; ")}`,
			"Run `theauth secret` and load the value from an environment variable.",
		),
	];
}

function cookieFindings(c: SecurityConfig): SecurityFinding[] {
	const out: SecurityFinding[] = [];
	const redirectCookie = c.redirects?.cookie;
	if (redirectCookie?.secure === false && !isLocal(c.baseUrl)) {
		out.push(
			finding(
				"sec.cookie.secure_off",
				"high",
				"redirects.cookie.secure is false on a non-local baseUrl, so the redirect chain cookie can travel over http",
				"Remove redirects.cookie.secure or set it to true, and serve the app over https.",
			),
		);
	}
	if (redirectCookie?.sameSite?.toLowerCase() === "none") {
		out.push(
			finding(
				"sec.cookie.samesite_none",
				"high",
				"redirects.cookie.sameSite is none, so browsers send the redirect chain cookie on every cross-site request",
				"Set redirects.cookie.sameSite to lax or strict unless you embed the app cross-site on purpose.",
			),
		);
	}
	const session = c.auth?.session;
	if (session && !isLocal(c.baseUrl)) {
		const name = session.cookieName ?? DEFAULT_SESSION_COOKIE;
		if (!name.startsWith("__Host-")) {
			out.push(
				finding(
					"sec.cookie.host_prefix_missing",
					"low",
					`The session cookie name "${name}" has no __Host- prefix, so a sibling subdomain can overwrite it`,
					"Set auth.session.cookieName to a name with the __Host- prefix (Secure, Path=/, no Domain).",
				),
			);
		}
	}
	return out;
}

function pbkdf2Findings(c: SecurityConfig, env: SecurityEnv): SecurityFinding[] {
	const raw = env.THEAUTH_PBKDF2_ITERATIONS;
	const envValue = raw !== undefined && raw.trim() !== "" ? Number(raw) : undefined;
	const flows: Array<[string, boolean, number | undefined]> = [
		["username.pbkdf2Iterations", c.username !== undefined, c.username?.pbkdf2Iterations],
		[
			"passwordReset.pbkdf2Iterations",
			c.passwordReset !== undefined,
			c.passwordReset?.pbkdf2Iterations,
		],
	];
	const low = flows.flatMap(([name, used, value]) => {
		if (!used) return [];
		const effective =
			value ?? (Number.isFinite(envValue) ? envValue : undefined) ?? PBKDF2_MIN_ITERATIONS;
		return (effective as number) < PBKDF2_MIN_ITERATIONS
			? [`${name} resolves to ${effective}`]
			: [];
	});
	if (low.length === 0) return [];
	return [
		finding(
			"sec.password.pbkdf2_low",
			"high",
			`PBKDF2 iterations are below ${PBKDF2_MIN_ITERATIONS}: ${low.join("; ")}`,
			"Remove the override or set it to 600000 or more.",
		),
	];
}

function throttleFindings(c: SecurityConfig, env: SecurityEnv): SecurityFinding[] {
	const out: SecurityFinding[] = [];
	const guarded =
		c.username !== undefined ||
		c.passwordReset !== undefined ||
		c.magicLink !== undefined ||
		c.emailOtp !== undefined ||
		c.phone !== undefined;
	const hasLimiter = c.plugins?.some((p) => p.id === RATE_LIMIT_PLUGIN_ID) ?? false;
	if (guarded && !hasLimiter) {
		out.push(
			finding(
				"sec.rate_limit.off",
				"medium",
				"Password or code flows are enabled but no rateLimit() plugin is registered, so the config adds no per-endpoint sign-in, reset or code limits (the createTheAuthHandler limit still applies if you mount it, and this check cannot see handler options)",
				"Add rateLimit() to plugins, or confirm the handler or a gateway in front enforces limits.",
			),
		);
	}
	const envOff = env.THEAUTH_LOGIN_LOCKOUT_DISABLED;
	const lockoutEnvOff = envOff === "1" || envOff?.toLowerCase() === "true";
	if (c.username !== undefined && (c.username.lockout === false || lockoutEnvOff)) {
		out.push(
			finding(
				"sec.lockout.off",
				"high",
				"Login lockout is turned off, so one account can be guessed without limit",
				"Remove username.lockout: false and THEAUTH_LOGIN_LOCKOUT_DISABLED to keep the default progressive lockout.",
			),
		);
	}
	return out;
}

function originFindings(c: SecurityConfig): SecurityFinding[] {
	const out: SecurityFinding[] = [];
	const wildcard = (c.allowedHosts ?? []).filter((h) => /^(https?:\/\/)?\*{1,2}(:\*)?$/.test(h));
	if (wildcard.length > 0) {
		out.push(
			finding(
				"sec.hosts.wildcard",
				"high",
				`allowedHosts contains ${wildcard.map((h) => `"${h}"`).join(", ")}, so any Host header is accepted for callback and magic link URLs`,
				"List the exact hosts or a suffix pattern such as *.example.com instead.",
			),
		);
	}
	if (c.redirects !== undefined && (c.redirects.allowedOrigins?.length ?? 0) === 0) {
		out.push(
			finding(
				"sec.redirect.allowlist_empty",
				"medium",
				"redirects.allowedOrigins is empty, so only same-origin return URLs work and the list was likely forgotten",
				"Set redirects.allowedOrigins to the origins that may receive a user after sign-in.",
			),
		);
	}
	return out;
}

function mcpFindings(c: SecurityConfig, env: SecurityEnv): SecurityFinding[] {
	if (!c.mcp?.enabled) return [];
	const mode = c.mcp.revocation?.mode ?? env.THEAUTH_MCP_REVOCATION_MODE;
	if (mode !== "offline") return [];
	return [
		finding(
			"sec.mcp.revocation_offline",
			"medium",
			"MCP revocation freshness is offline, so revoked tokens stay valid until they expire",
			"Set mcp.revocation.mode to live or cached (live is the default when the module has a database).",
		),
	];
}

function mountFindings(c: SecurityConfig): SecurityFinding[] {
	const out: SecurityFinding[] = [];
	const handlers: Array<[string, string, { trustedServerUse?: boolean } | undefined]> = [
		["sec.org.no_auth", "org", c.org],
		["sec.api_keys.no_auth", "apiKeys", c.apiKeys],
	];
	for (const [id, name, handler] of handlers) {
		if (handler?.trustedServerUse !== true) continue;
		out.push(
			finding(
				id,
				"high",
				`${name}.trustedServerUse is true, so handleRequest acts on ids in the request without resolving a caller`,
				`Pass resolveUser to the ${name} handler and remove ${name}.trustedServerUse, unless your own code authorizes every call first.`,
			),
		);
	}
	return out;
}

const SEVERITY_ORDER: SecuritySeverity[] = ["high", "medium", "low"];

/** Runs every security rule. Findings come back most serious first, then by id. */
export function lintSecurity(config: SecurityConfig, env: SecurityEnv = {}): SecurityFinding[] {
	const all = [
		...secretFindings(config, env),
		...cookieFindings(config),
		...pbkdf2Findings(config, env),
		...throttleFindings(config, env),
		...originFindings(config),
		...mcpFindings(config, env),
		...mountFindings(config),
	];
	return all.sort(
		(a, b) =>
			SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) ||
			a.id.localeCompare(b.id),
	);
}

/** Every finding id the linter can emit, for docs and tests. */
export const SECURITY_FINDING_IDS = [
	"sec.session.secret_weak",
	"sec.cookie.secure_off",
	"sec.cookie.samesite_none",
	"sec.cookie.host_prefix_missing",
	"sec.password.pbkdf2_low",
	"sec.rate_limit.off",
	"sec.lockout.off",
	"sec.hosts.wildcard",
	"sec.redirect.allowlist_empty",
	"sec.mcp.revocation_offline",
	"sec.org.no_auth",
	"sec.api_keys.no_auth",
] as const;

export interface SecurityReport {
	ok: boolean;
	failOn: SecuritySeverity;
	findings: SecurityFinding[];
}

export function buildSecurityReport(
	findings: SecurityFinding[],
	failOn: SecuritySeverity,
): SecurityReport {
	const ok = !findings.some(
		(f) => SECURITY_SEVERITY_RANK[f.severity] >= SECURITY_SEVERITY_RANK[failOn],
	);
	return { ok, failOn, findings };
}

export function formatSecurityReport(report: SecurityReport, json: boolean): string {
	if (json) return `${JSON.stringify(report, null, 2)}\n`;
	if (report.findings.length === 0) return "No security findings.\n";
	const lines = report.findings.flatMap((f) => [
		`${f.severity.toUpperCase().padEnd(6)} ${f.id}  ${f.message}`,
		`       fix: ${f.fix}`,
		`       docs: ${f.docs}`,
	]);
	const high = report.findings.filter((f) => f.severity === "high").length;
	lines.push("", `${report.findings.length} finding(s), ${high} high.`);
	return `${lines.join("\n")}\n`;
}
