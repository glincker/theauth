import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { TheAuthConfig } from "@glinr/theauth";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { SecurityConfig } from "../src/security-doctor.js";
import { buildSecurityReport, lintSecurity, SECURITY_FINDING_IDS } from "../src/security-doctor.js";
import { parseSecurityArgs, runSecurityDoctor } from "../src/security-doctor-run.js";

const RATE = [{ id: "theauth-rate-limit" }];
const STRONG = "k9Vq2mXw7Lr4Tz8Nb1Hc6Yp3Js5Gd0FaQe";
const CLEAN: SecurityConfig = {
	secret: STRONG,
	baseUrl: "https://app.glinr.com",
	auth: { session: { secret: STRONG, cookieName: "__Host-theauth" } },
};

const ATTEST = async () => ({ ok: true });
const FLEET_CATALOG = { "mqtt:fleet/*/temp": ["read"], "mqtt:fleet/**": ["subscribe"] };

const ids = (c: SecurityConfig, env = {}) => lintSecurity(c, env).map((f) => f.id);

/** The same shapes typed as the real config. Assigning a TheAuthConfig to SecurityConfig proves the field names exist. */
const REAL = {
	database: { provider: "sqlite", url: ":memory:" },
	secret: STRONG,
	baseUrl: "https://app.glinr.com",
	allowedHosts: ["app.glinr.com", "*.glinr.com"],
	auth: { session: { secret: STRONG, cookieName: "__Host-theauth" } },
	username: { pbkdf2Iterations: 600_000, lockout: false },
	redirects: { allowedOrigins: [], cookie: { secure: false, sameSite: "none" } },
	mcp: { enabled: true, revocation: { mode: "offline", clockSkewMs: 5 } },
	org: { trustedServerUse: true },
	apiKeys: { trustedServerUse: true },
	plugins: [{ id: "theauth-rate-limit" }],
} satisfies TheAuthConfig;

describe("lintSecurity", () => {
	it("is clean for a hardened config", () => {
		expect(lintSecurity(CLEAN)).toEqual([]);
	});

	it("reads a real TheAuthConfig", () => {
		const real: SecurityConfig = REAL;
		expect(ids(real).sort()).toEqual(
			[
				"sec.cookie.samesite_none",
				"sec.cookie.secure_off",
				"sec.lockout.off",
				"sec.redirect.allowlist_empty",
				"sec.mcp.revocation_offline",
				"sec.org.no_auth",
				"sec.api_keys.no_auth",
			].sort(),
		);
	});

	const cases: Array<[string, SecurityConfig, Record<string, string>?]> = [
		["sec.session.secret_weak", { ...CLEAN, secret: "short" }],
		["sec.session.secret_weak", { ...CLEAN, secret: "change-me-to-a-long-placeholder-value-1" }],
		["sec.session.secret_weak", { ...CLEAN, auth: { session: { secret: "tiny" } } }],
		["sec.session.secret_weak", { ...CLEAN, mcp: { enabled: true, signingSecret: "tiny" } }],
		[
			"sec.cookie.secure_off",
			{
				...CLEAN,
				redirects: { allowedOrigins: ["https://a.glinr.com"], cookie: { secure: false } },
			},
		],
		[
			"sec.cookie.samesite_none",
			{
				...CLEAN,
				redirects: { allowedOrigins: ["https://a.glinr.com"], cookie: { sameSite: "none" } },
			},
		],
		["sec.cookie.host_prefix_missing", { ...CLEAN, auth: { session: { secret: STRONG } } }],
		[
			"sec.cookie.host_prefix_missing",
			{ ...CLEAN, auth: { session: { secret: STRONG, cookieName: "sid" } } },
		],
		["sec.password.pbkdf2_low", { ...CLEAN, username: { pbkdf2Iterations: 100_000 } }],
		["sec.password.pbkdf2_low", { ...CLEAN, passwordReset: { pbkdf2Iterations: 1000 } }],
		["sec.password.pbkdf2_low", { ...CLEAN, username: {} }, { THEAUTH_PBKDF2_ITERATIONS: "1000" }],
		["sec.rate_limit.off", { ...CLEAN, username: {}, plugins: [{ id: "theauth-2fa" }] }],
		["sec.lockout.off", { ...CLEAN, username: { lockout: false }, plugins: RATE }],
		[
			"sec.lockout.off",
			{ ...CLEAN, username: {}, plugins: RATE },
			{ THEAUTH_LOGIN_LOCKOUT_DISABLED: "true" },
		],
		["sec.hosts.wildcard", { ...CLEAN, allowedHosts: ["app.glinr.com", "*"] }],
		["sec.hosts.wildcard", { ...CLEAN, allowedHosts: ["https://**"] }],
		["sec.redirect.allowlist_empty", { ...CLEAN, redirects: { allowedOrigins: [] } }],
		[
			"sec.mcp.revocation_offline",
			{ ...CLEAN, mcp: { enabled: true, revocation: { mode: "offline" } } },
		],
		[
			"sec.mcp.revocation_offline",
			{ ...CLEAN, mcp: { enabled: true } },
			{ THEAUTH_MCP_REVOCATION_MODE: "offline" },
		],
		["sec.org.no_auth", { ...CLEAN, org: { trustedServerUse: true } }],
		["sec.api_keys.no_auth", { ...CLEAN, apiKeys: { trustedServerUse: true } }],
		["sec.api_keys.no_scope_resolver", { ...CLEAN, apiKeys: {} }],
		[
			"sec.device.path_matching_off",
			{ ...CLEAN, devices: { attestation: { verify: ATTEST } }, permissions: FLEET_CATALOG },
		],
		[
			"sec.device.mid_wildcard",
			{
				...CLEAN,
				devices: { attestation: { verify: ATTEST } },
				permissions: { "mqtt:fleet:*:temp": ["read"] },
			},
		],
		[
			"sec.device.mid_wildcard",
			{
				...CLEAN,
				resourceMatching: "path",
				devices: { attestation: { verify: ATTEST } },
				permissions: { "mqtt:fleet/#/temp": ["read"] },
			},
		],
		[
			"sec.device.bundle_ttl_long",
			{ ...CLEAN, devices: { bundleTtlSeconds: 7200, attestation: { verify: ATTEST } } },
		],
		["sec.device.no_attestation", { ...CLEAN, devices: {} }],
		["sec.approval.no_step_up", { ...CLEAN, approval: { ttl: 300 } as SecurityConfig["approval"] }],
		[
			"sec.agent.dpop_not_required",
			{ ...CLEAN, agents: { enabled: true }, permissions: { "docs:*": ["read", "write"] } },
		],
		[
			"sec.agent.dpop_not_required",
			{ ...CLEAN, agents: { enabled: true, defaultPermissions: ["docs:write"] } },
		],
	];

	it.each(cases)("fires %s", (id, config, env) => {
		expect(ids(config, env)).toContain(id);
	});

	it("covers every documented id", () => {
		const fired = new Set(cases.map(([id]) => id));
		expect([...fired].sort()).toEqual([...SECURITY_FINDING_IDS].sort());
	});

	it("stays quiet when the safe setting is present", () => {
		expect(
			lintSecurity({
				...CLEAN,
				allowedHosts: ["app.glinr.com", "*.glinr.com", "**.preview.glinr.com", "localhost:*"],
				username: { pbkdf2Iterations: 600_000 },
				passwordReset: {},
				plugins: RATE,
				redirects: {
					allowedOrigins: ["https://app.glinr.com"],
					cookie: { secure: true, sameSite: "lax" },
				},
				mcp: { enabled: true, revocation: { mode: "live" } },
				org: { trustedServerUse: false },
				apiKeys: {},
			}),
		).toEqual([]);
	});

	it("stays quiet on a hardened device, approval and agent setup", () => {
		expect(
			lintSecurity({
				...CLEAN,
				resourceMatching: "path",
				org: {},
				apiKeys: {},
				devices: { bundleTtlSeconds: 3600, attestation: { required: true, verify: ATTEST } },
				permissions: { "mqtt:fleet/*/temp": ["read"], "mqtt:fleet/**": ["subscribe"] },
				approval: { requireAcr: "phr", maxAuthAge: 300 },
				agents: {
					enabled: true,
					confirmation: { required: true },
					defaultPermissions: ["docs:write"],
				},
			}),
		).toEqual([]);
	});

	it("keeps read only agents and an apiKeys grantablePermissions resolver quiet", () => {
		expect(
			ids({ ...CLEAN, agents: { enabled: true }, permissions: { "docs:*": ["read"] } }),
		).toEqual([]);
		expect(ids({ ...CLEAN, apiKeys: { grantablePermissions: () => [] } })).toEqual([]);
		expect(ids({ ...CLEAN, apiKeys: { trustedServerUse: true } })).not.toContain(
			"sec.api_keys.no_scope_resolver",
		);
	});

	it("reads the fleet fields of a real TheAuthConfig", () => {
		const real = {
			database: { provider: "sqlite", url: ":memory:" },
			agents: { enabled: true, defaultPermissions: ["docs:write"], confirmation: {} },
			devices: { bundleTtlSeconds: 86_400 },
			resourceMatching: "colon",
			permissions: { "mqtt:fleet/*/temp": ["read"] },
			approval: { ttl: 300 },
			apiKeys: {},
		} satisfies TheAuthConfig;
		const config: SecurityConfig = real;
		expect(ids(config).sort()).toEqual(
			[
				"sec.agent.dpop_not_required",
				"sec.api_keys.no_scope_resolver",
				"sec.approval.no_step_up",
				"sec.device.bundle_ttl_long",
				"sec.device.mid_wildcard",
				"sec.device.no_attestation",
				"sec.device.path_matching_off",
			].sort(),
		);
	});

	it("does not flag cookie, lockout or rate limit rules for fields it does not own", () => {
		expect(ids({ ...CLEAN, username: {}, plugins: RATE })).toEqual([]);
		expect(ids({ secret: STRONG, baseUrl: "http://localhost:3000" })).toEqual([]);
	});

	it("gives each finding an id, severity, fix and docs link", () => {
		for (const f of lintSecurity({ username: { lockout: false } })) {
			expect(f.id).toMatch(/^sec\./);
			expect(f.fix.length).toBeGreaterThan(0);
			expect(f.docs).toContain(`#${f.id.replace(/[._]/g, "-")}`);
		}
	});

	it("sorts high before medium before low", () => {
		const sev = lintSecurity({
			username: { lockout: false },
			redirects: {},
			baseUrl: "https://a.glinr.com",
			auth: { session: { secret: STRONG } },
		}).map((f) => f.severity);
		expect(sev.length).toBeGreaterThan(2);
		expect(sev).toEqual(
			[...sev].sort(
				(a, b) => ["high", "medium", "low"].indexOf(a) - ["high", "medium", "low"].indexOf(b),
			),
		);
	});
});

describe("buildSecurityReport", () => {
	it("fails only at or above the threshold", () => {
		const low = lintSecurity({ ...CLEAN, auth: { session: { secret: STRONG } } });
		expect(buildSecurityReport(low, "high").ok).toBe(true);
		expect(buildSecurityReport(low, "low").ok).toBe(false);
	});
});

describe("parseSecurityArgs", () => {
	it("parses flags", () => {
		expect(
			parseSecurityArgs(["--security", "--json", "--fail-on=medium", "--config", "a.json"], "/c"),
		).toMatchObject({
			json: true,
			failOn: "medium",
			config: "a.json",
			error: null,
		});
		expect(parseSecurityArgs(["--fail-on", "x"], "/c").error).not.toBeNull();
		expect(parseSecurityArgs(["--nope"], "/c").error).toContain("Unknown option");
	});
});

describe("runSecurityDoctor", () => {
	let dir: string;
	beforeEach(async () => {
		dir = await mkdtemp(join(tmpdir(), "sec-doctor-"));
	});
	afterEach(async () => {
		await rm(dir, { recursive: true, force: true });
	});

	it("exits 1 with JSON output on a high finding", async () => {
		await writeFile(
			join(dir, "theauth.config.json"),
			JSON.stringify({ ...CLEAN, username: { lockout: false }, plugins: RATE }),
		);
		const out = await runSecurityDoctor(parseSecurityArgs(["--json"], dir), {});
		expect(out.code).toBe(1);
		const parsed = JSON.parse(out.text) as { ok: boolean; findings: Array<{ id: string }> };
		expect(parsed.ok).toBe(false);
		expect(parsed.findings.map((f) => f.id)).toContain("sec.lockout.off");
	});

	it("exits 0 for a clean config and 2 for a missing file", async () => {
		await writeFile(join(dir, "c.json"), JSON.stringify(CLEAN));
		expect((await runSecurityDoctor(parseSecurityArgs(["--config", "c.json"], dir), {})).code).toBe(
			0,
		);
		expect((await runSecurityDoctor(parseSecurityArgs([], dir), {})).code).toBe(2);
	});

	it("loads an ES module config", async () => {
		await writeFile(
			join(dir, "theauth.config.mjs"),
			`export default ${JSON.stringify({ ...CLEAN, allowedHosts: ["*"] })};`,
		);
		const out = await runSecurityDoctor(parseSecurityArgs([], dir), {});
		expect(out.code).toBe(1);
		expect(out.text).toContain("sec.hosts.wildcard");
	});
});
