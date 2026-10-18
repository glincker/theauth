import { describe, expect, it } from "vitest";
import { runLiveDoctorChecks } from "../src/doctor-live.js";
import type { RuleConfig, RuleEnv } from "../src/doctor-rules.js";
import { configRules } from "../src/doctor-rules.js";
import type { DoctorCheck } from "../src/tools-commands.js";
import { formatDoctor } from "../src/tools-commands.js";

const STRONG_SECRET = "k9Vq2mXw7Lr4Tz8Nb1Hc6Yp3Js5Gd0FaQe";
const noConfig = async () => null;
const MCP_OK: NonNullable<RuleConfig["mcp"]> = {
	enabled: true,
	consentPage: "https://app.example.com/consent",
	jtiDenylist: { revoke: async () => undefined },
	registration: { agentForClient: async () => undefined },
	revocation: { mode: "live" },
	clientIdMetadataDocuments: { enabled: false },
};

interface RuleCase {
	id: string;
	name: string;
	config: RuleConfig;
	env?: RuleEnv;
	/** Expected: the rule id fires with this status and severity, or it must not fire. */
	fires?: { status: "fail" | "warn"; severity: "info" | "warn" | "fail" };
}

const cases: RuleCase[] = [
	{
		id: "secret.weak",
		name: "a short signing secret",
		config: { secret: "too-short" },
		fires: { status: "fail", severity: "fail" },
	},
	{
		id: "secret.weak",
		name: "a placeholder mcp.signingSecret",
		config: { mcp: { enabled: true, signingSecret: "change-me-to-a-real-secret-value-123456" } },
		fires: { status: "fail", severity: "fail" },
	},
	{ id: "secret.weak", name: "a random 32+ char secret", config: { secret: STRONG_SECRET } },
	{
		id: "session.ttl_long",
		name: "a session maxAge of 60 days",
		config: { auth: { session: { secret: STRONG_SECRET, maxAge: 60 * 24 * 60 * 60 } } },
		fires: { status: "warn", severity: "warn" },
	},
	{
		id: "session.ttl_long",
		name: "a session maxAge of 7 days",
		config: { auth: { session: { secret: STRONG_SECRET, maxAge: 7 * 24 * 60 * 60 } } },
	},
	{
		id: "cookie.insecure_http",
		name: "plain http on a public host",
		config: { baseUrl: "http://auth.example.com" },
		fires: { status: "fail", severity: "fail" },
	},
	{ id: "cookie.insecure_http", name: "https", config: { baseUrl: "https://auth.example.com" } },
	{
		id: "cookie.insecure_http",
		name: "plain http on localhost",
		config: { baseUrl: "http://localhost:3000" },
	},
	{
		id: "network.trusted_proxies_empty",
		name: "forwarded headers trusted with no proxy",
		config: { trustForwardedHeaders: true },
		fires: { status: "warn", severity: "warn" },
	},
	{
		id: "network.trusted_proxies_empty",
		name: "forwarded headers trusted behind one proxy",
		config: { trustForwardedHeaders: true, trustedProxy: { trustedProxyCount: 1 } },
	},
	{
		id: "mfa.none_enabled",
		name: "username sign-in with no totp or passkey",
		config: { username: {} },
		fires: { status: "warn", severity: "warn" },
	},
	{
		id: "mfa.none_enabled",
		name: "username sign-in with totp",
		config: { username: {}, totp: {} },
	},
	{
		id: "password.min_length_low",
		name: "a username minLength of 8 (default)",
		config: { username: {} },
		fires: { status: "warn", severity: "warn" },
	},
	{
		id: "password.min_length_low",
		name: "a username minLength of 12",
		config: { username: { password: { minLength: 12 } } },
	},
	{
		id: "password.pbkdf2_iterations_low",
		name: "a username iteration override of 100000",
		config: { username: { pbkdf2Iterations: 100_000 } },
		fires: { status: "warn", severity: "warn" },
	},
	{
		id: "password.pbkdf2_iterations_low",
		name: "a low THEAUTH_PBKDF2_ITERATIONS env value for password reset",
		config: { passwordReset: {} },
		env: { THEAUTH_PBKDF2_ITERATIONS: "200000" },
		fires: { status: "warn", severity: "warn" },
	},
	{
		id: "password.pbkdf2_iterations_low",
		name: "the 600000 default",
		config: { username: {}, passwordReset: { pbkdf2Iterations: 600_000 } },
	},
	{
		id: "webauthn.rpid_mismatch",
		name: "an rpId for another domain",
		config: { baseUrl: "https://auth.example.com", passkey: { rpId: "other.dev" } },
		fires: { status: "fail", severity: "fail" },
	},
	{
		id: "webauthn.rpid_mismatch",
		name: "the registrable parent as rpId",
		config: { baseUrl: "https://auth.example.com", passkey: { rpId: "example.com" } },
	},
	{
		id: "saml.tracker_in_memory",
		name: "SAML providers with no shared storage",
		config: { sso: { saml: [{ id: "okta" }] } },
		fires: { status: "warn", severity: "warn" },
	},
	{
		id: "saml.tracker_in_memory",
		name: "SAML providers with secondaryStorage",
		config: { sso: { saml: [{ id: "okta" }] }, secondaryStorage: {} },
	},
	{
		id: "mcp.offline_no_jti_denylist",
		name: "offline revocation with no denylist",
		config: { mcp: { enabled: true, revocation: { mode: "offline" } } },
		fires: { status: "warn", severity: "warn" },
	},
	{
		id: "mcp.offline_no_jti_denylist",
		name: "offline revocation set by THEAUTH_MCP_REVOCATION_MODE with no denylist",
		config: { mcp: { enabled: true } },
		env: { THEAUTH_MCP_REVOCATION_MODE: "offline" },
		fires: { status: "warn", severity: "warn" },
	},
	{
		id: "mcp.offline_no_jti_denylist",
		name: "offline revocation with a denylist",
		config: { mcp: { ...MCP_OK, revocation: { mode: "offline" } } },
	},
	{
		id: "cimd.no_host_allowlist",
		name: "client metadata documents with no allowlist and no resolver",
		config: { mcp: { ...MCP_OK, clientIdMetadataDocuments: { enabled: true } } },
		fires: { status: "warn", severity: "warn" },
	},
	{
		id: "cimd.no_host_allowlist",
		name: "client metadata documents with allowedHosts",
		config: {
			mcp: {
				...MCP_OK,
				clientIdMetadataDocuments: { enabled: true, allowedHosts: ["*.example.com"] },
			},
		},
	},
	{
		id: "mcp.consent_page_missing",
		name: "MCP enabled with no consentPage",
		config: { mcp: { enabled: true } },
		fires: { status: "warn", severity: "warn" },
	},
	{ id: "mcp.consent_page_missing", name: "MCP with a consentPage", config: { mcp: MCP_OK } },
	{
		id: "mcp.registration_open",
		name: "open registration with no agent binding",
		config: { mcp: { ...MCP_OK, registration: { enabled: true } } },
		fires: { status: "warn", severity: "warn" },
	},
	{
		id: "mcp.registration_open",
		name: "registration disabled",
		config: { mcp: { ...MCP_OK, registration: { enabled: false } } },
	},
	{
		id: "hooks.timeout_disabled",
		name: "a beforeAuthorize hook with timeoutMs 0",
		config: {
			hooks: { beforeAuthorize: async () => undefined },
			hookSafety: { timeoutMs: 0 },
		},
		fires: { status: "warn", severity: "warn" },
	},
	{
		id: "hooks.timeout_disabled",
		name: "a hook with the default timeout",
		config: { hooks: { beforeAuthorize: async () => undefined } },
	},
	{
		id: "audit.tamper_evident_off",
		name: "audit without tamperEvident",
		config: { audit: {} },
		fires: { status: "warn", severity: "info" },
	},
	{
		id: "audit.tamper_evident_off",
		name: "audit with tamperEvident and an hmacKey",
		config: { audit: { tamperEvident: true, hmacKey: STRONG_SECRET } },
	},
	{
		id: "audit.hmac_key_missing",
		name: "tamperEvident audit without an hmacKey",
		config: { audit: { tamperEvident: true } },
		fires: { status: "warn", severity: "warn" },
	},
	{
		id: "audit.hmac_key_missing",
		name: "tamperEvident audit with an hmacKey",
		config: { audit: { tamperEvident: true, hmacKey: STRONG_SECRET } },
	},
];

describe("config rules (table)", () => {
	for (const c of cases) {
		const label = `${c.id}: ${c.name}`;
		it(label, () => {
			const found = configRules(c.config, c.env ?? {}).filter((r) => r.id === c.id);
			if (c.fires === undefined) {
				expect(found, label).toEqual([]);
				return;
			}
			expect(found, label).toHaveLength(1);
			expect(found[0]).toMatchObject({
				id: c.id,
				status: c.fires.status,
				severity: c.fires.severity,
			});
			expect(found[0]?.message.length).toBeGreaterThan(0);
			expect(found[0]?.fix?.length).toBeGreaterThan(0);
		});
	}

	it("every rule id has a positive and a negative case", () => {
		const ids = new Set(cases.map((c) => c.id));
		for (const id of ids) {
			expect(
				cases.some((c) => c.id === id && c.fires !== undefined),
				`${id} positive`,
			).toBe(true);
			expect(
				cases.some((c) => c.id === id && c.fires === undefined),
				`${id} negative`,
			).toBe(true);
		}
		expect(ids.size).toBe(16);
	});

	it("never echoes a secret value in a message", () => {
		const leaked = configRules({ secret: "short-secret-value-xyz" }, {});
		expect(JSON.stringify(leaked)).not.toContain("short-secret-value-xyz");
	});

	it("raises nothing without a loaded config", () => {
		expect(configRules(null, {})).toEqual([]);
	});
});

interface FakeResponse {
	status: number;
	headers?: Record<string, string>;
}

/** A fetch stub keyed by pathname. The handler sees the request init, so CORS probes can be told apart. */
function fakeFetch(routes: Record<string, (init?: RequestInit) => FakeResponse>): typeof fetch {
	return (async (input: string | URL | Request, init?: RequestInit) => {
		const path = new URL(String(input)).pathname;
		const handler = routes[path];
		const res = handler ? handler(init) : { status: 404 };
		return new Response("{}", {
			status: res.status,
			headers: { "content-type": "application/json", ...res.headers },
		});
	}) as typeof fetch;
}

const agentsRoute = (headers: Record<string, string>) => (init?: RequestInit) => {
	const sent = new Headers(init?.headers);
	const cors = sent.has("origin") ? { "access-control-allow-origin": "*" } : {};
	return { status: 401, headers: { ...headers, ...cors } };
};

describe("live rules", () => {
	const base = "https://auth.example.com/api/theauth";

	it("fails cors.wildcard when any origin is granted", async () => {
		const checks = await runLiveDoctorChecks({
			cwd: ".",
			url: base,
			loadConfig: noConfig,
			fetch: fakeFetch({
				"/api/theauth/agents": agentsRoute({ "strict-transport-security": "max-age=1" }),
			}),
		});
		expect(checks.find((c) => c.id === "cors.wildcard")).toMatchObject({
			status: "fail",
			severity: "fail",
		});
	});

	it("passes cors.wildcard (no entry) for a server that grants no origin", async () => {
		const checks = await runLiveDoctorChecks({
			cwd: ".",
			url: base,
			loadConfig: noConfig,
			fetch: fakeFetch({
				"/api/theauth/agents": () => ({
					status: 401,
					headers: { "strict-transport-security": "max-age=1" },
				}),
			}),
		});
		expect(checks.map((c) => c.id)).not.toContain("cors.wildcard");
		expect(checks.map((c) => c.id)).not.toContain("headers.security_off_https");
	});

	it("reports headers.security_off_https as info on https without HSTS", async () => {
		const checks = await runLiveDoctorChecks({
			cwd: ".",
			url: base,
			loadConfig: noConfig,
			fetch: fakeFetch({ "/api/theauth/agents": agentsRoute({}) }),
		});
		expect(checks.find((c) => c.id === "headers.security_off_https")).toMatchObject({
			status: "warn",
			severity: "info",
		});
	});

	it("does not report headers.security_off_https over plain http", async () => {
		const checks = await runLiveDoctorChecks({
			cwd: ".",
			url: "http://localhost:3000/api/theauth",
			loadConfig: noConfig,
			fetch: fakeFetch({ "/api/theauth/agents": agentsRoute({}) }),
		});
		expect(checks.map((c) => c.id)).not.toContain("headers.security_off_https");
	});
});

describe("exit code and json for rules", () => {
	it("exits nonzero only for fail rules, and keeps severity in the json", () => {
		const warnOnly = configRules({ username: {} }, {}) as DoctorCheck[];
		expect(formatDoctor(warnOnly, false).ok).toBe(true);
		const failing = configRules({ baseUrl: "http://auth.example.com" }, {}) as DoctorCheck[];
		expect(formatDoctor(failing, false).ok).toBe(false);
		const parsed = JSON.parse(formatDoctor(failing, true).text) as {
			ok: boolean;
			checks: Array<{ id: string; status: string; severity?: string; fix?: string }>;
		};
		expect(parsed.ok).toBe(false);
		expect(parsed.checks[0]).toMatchObject({
			id: "cookie.insecure_http",
			status: "fail",
			severity: "fail",
		});
		expect(typeof parsed.checks[0]?.fix).toBe("string");
	});
});
