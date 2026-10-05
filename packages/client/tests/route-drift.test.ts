import { readFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import { createTheAuthGoClient } from "../src/go-client.js";
import type { TheAuthGoClient } from "../src/go-types.js";

interface Manifest {
	source: { repo: string; commit: string };
	routes: Array<{ method: string; path: string }>;
}

const manifest = JSON.parse(
	readFileSync(new URL("../routes.manifest.json", import.meta.url), "utf8"),
) as Manifest;
const placeholders = (path: string) => path.replace(/\{[^}]+\}/g, "{id}");
const known = new Set(manifest.routes.map((r) => `${r.method} ${placeholders(r.path)}`));

const ID = "01HZZZZZZZZZZZZZZZZZZZZZZZ";
type Call = (c: TheAuthGoClient) => Promise<unknown>;

const calls: Record<string, Call> = {
	login: (c) => c.login({ email: "a", password: "b" }),
	signup: (c) => c.signup({ email: "a", password: "b", setupToken: "t" }),
	logout: (c) => c.logout(),
	forgotPassword: (c) => c.forgotPassword("a"),
	resetPassword: (c) => c.resetPassword({ token: "t", newPassword: "n" }),
	changePassword: (c) => c.changePassword({ currentPassword: "a", newPassword: "b" }),
	"bootstrap.status": (c) => c.bootstrap.status(),
	"stepUp.verify": (c) => c.stepUp.verify({ method: "password", password: "p" }),
	"apiTokens.list": (c) => c.apiTokens.list({ all: true, ownerId: ID }),
	"apiTokens.mint": (c) => c.apiTokens.mint({ name: "n", abilities: [] }),
	"apiTokens.revoke": (c) => c.apiTokens.revoke(ID),
	"apiTokens.current": (c) => c.apiTokens.current(),
	"apiTokens.revokeCurrent": (c) => c.apiTokens.revokeCurrent(),
	"agents.list": (c) => c.agents.list(),
	"agents.register": (c) => c.agents.register({ name: "n" }),
	"agents.revoke": (c) => c.agents.revoke(ID, "r"),
	"delegations.list": (c) => c.delegations.list(),
	"delegations.grant": (c) =>
		c.delegations.grant({ agentId: ID, scope: [], resource: "r", maxDurationSeconds: 1 }),
	"delegations.revoke": (c) => c.delegations.revoke(ID),
	"device.code": (c) => c.device.code(),
	"device.token": (c) => c.device.token("dc"),
	"device.info": (c) => c.device.info("U-1"),
	"device.approve": (c) => c.device.approve("U-1"),
	"device.deny": (c) => c.device.deny("U-1"),
	"session.get": (c) => c.session.get(),
	"session.revokeCurrent": (c) => c.session.revokeCurrent(),
	"session.list": (c) => c.session.list(),
	"session.revoke": (c) => c.session.revoke(ID),
	"session.revokeOthers": (c) => c.session.revokeOthers(),
	"passkeys.list": (c) => c.passkeys.list(),
	"passkeys.remove": (c) => c.passkeys.remove(ID),
	"passkeys.rename": (c) => c.passkeys.rename(ID, "n"),
	"totp.enrollBegin": (c) => c.totp.enrollBegin(),
	"totp.enrollFinish": (c) => c.totp.enrollFinish({ enrollmentId: "e", code: "1" }),
	"totp.verify": (c) => c.totp.verify("1"),
	"totp.recovery": (c) => c.totp.recovery("r"),
	"totp.disable": (c) => c.totp.disable(),
	"totp.status": (c) => c.totp.status(),
	"totp.regenerateRecoveryCodes": (c) => c.totp.regenerateRecoveryCodes(),
};

// Browser ceremonies need WebAuthn, so they cannot run here; their routes are pinned by hand.
const ceremonies: Record<string, string[]> = {
	"passkeys.register": [
		"POST /auth/webauthn/register/begin",
		"POST /auth/webauthn/register/finish",
	],
	"passkeys.login": ["POST /auth/webauthn/login/begin", "POST /auth/webauthn/login/finish"],
	"stepUp.passkey": ["POST /auth/step-up/passkey/begin", "POST /auth/step-up"],
};

const skipped = new Set(["passkeys.isSupported", "device.poll"]);

function leaves(obj: object, prefix = ""): string[] {
	return Object.entries(obj).flatMap(([k, v]) => {
		const name = prefix ? `${prefix}.${k}` : k;
		if (typeof v === "function") return [name];
		return v && typeof v === "object" ? leaves(v, name) : [];
	});
}

function normalize(url: string): string {
	return url.split("?")[0]?.replace(ID, "{id}") ?? url;
}

describe("route manifest drift guard", () => {
	it("records the Go commit it was curated from", () => {
		expect(manifest.source.commit).toMatch(/^[0-9a-f]{40}$/);
	});

	it("covers every client method", () => {
		const all = leaves(createTheAuthGoClient());
		const covered = new Set([...Object.keys(calls), ...Object.keys(ceremonies), ...skipped]);
		expect(all.filter((n) => !covered.has(n))).toEqual([]);
	});

	it.each(Object.entries(calls))("%s hits a route the Go router mounts", async (_name, run) => {
		const fetchFn = vi.fn().mockResolvedValue({
			ok: true,
			status: 204,
			headers: new Headers(),
			text: () => Promise.resolve(""),
		});
		await run(createTheAuthGoClient({ fetch: fetchFn as unknown as typeof fetch }));
		expect(fetchFn).toHaveBeenCalledTimes(1);
		const [url, init] = fetchFn.mock.calls[0] as [string, RequestInit];
		expect(known).toContain(`${init.method} ${normalize(url)}`);
	});

	it.each(Object.entries(ceremonies))("%s routes are in the manifest", (_name, routes) => {
		for (const r of routes) expect(known).toContain(r);
	});
});
