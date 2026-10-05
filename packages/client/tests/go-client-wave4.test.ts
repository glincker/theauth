import { describe, expect, it, vi } from "vitest";
import { createTheAuthGoClient } from "../src/go-client.js";
import { isBearerRequired } from "../src/go-errors.js";

interface Reply {
	status: number;
	body?: unknown;
}

function res(r: Reply) {
	return {
		ok: r.status >= 200 && r.status < 300,
		status: r.status,
		headers: new Headers(),
		text: () => Promise.resolve(r.body === undefined ? "" : JSON.stringify(r.body)),
	};
}

function setup(reply: Reply, getToken?: () => string | null | undefined) {
	const fetchFn = vi.fn().mockResolvedValue(res(reply));
	const api = createTheAuthGoClient({ fetch: fetchFn as unknown as typeof fetch, getToken });
	const sent = () => {
		const [url, init] = fetchFn.mock.calls[0] as [string, RequestInit];
		return {
			url,
			init,
			headers: init.headers as Record<string, string>,
			body: init.body ? JSON.parse(init.body as string) : undefined,
		};
	};
	return { api, sent };
}

describe("bearer option", () => {
	it("sets Authorization and omits credentials when a token is supplied", async () => {
		const { api, sent } = setup({ status: 204 }, () => "tk_abc");
		await api.apiTokens.revokeCurrent();
		const s = sent();
		expect(s.headers.Authorization).toBe("Bearer tk_abc");
		expect(s.init.credentials).toBe("omit");
	});

	it("falls back to cookies when the token is empty", async () => {
		const { api, sent } = setup({ status: 204 }, () => null);
		await api.apiTokens.revokeCurrent();
		expect(sent().headers.Authorization).toBeUndefined();
		expect(sent().init.credentials).toBe("include");
	});
});

describe("apiTokens.current", () => {
	const body = { id: "t1", name: "ci", kind: "agent", abilities: ["read"], ownerId: "u1" };

	it("GETs /tokens/current", async () => {
		const { api, sent } = setup({ status: 200, body }, () => "tk");
		const r = await api.apiTokens.current();
		expect(sent().url).toBe("/auth/tokens/current");
		expect(sent().init.method).toBe("GET");
		expect(r).toEqual({ success: true, data: body });
	});

	it("types the 403 for a cookie session", async () => {
		const { api } = setup({
			status: 403,
			body: { code: "auth.bearer_required", message: "bearer only" },
		});
		const r = await api.apiTokens.current();
		expect(r.success).toBe(false);
		if (!r.success) {
			expect(isBearerRequired(r.error)).toBe(true);
			expect(r.error.status).toBe(403);
		}
	});

	it("DELETEs /tokens/current", async () => {
		const { api, sent } = setup({ status: 204 }, () => "tk");
		expect(await api.apiTokens.revokeCurrent()).toEqual({ success: true, data: null });
		expect(sent().url).toBe("/auth/tokens/current");
		expect(sent().init.method).toBe("DELETE");
	});
});

describe("agents", () => {
	it("unwraps the list", async () => {
		const { api, sent } = setup({ status: 200, body: { agents: [{ id: "a1" }] } });
		const r = await api.agents.list();
		expect(sent().url).toBe("/auth/account/agents");
		expect(r).toEqual({ success: true, data: [{ id: "a1" }] });
	});

	it("registers and returns the one-time credential", async () => {
		const created = { agent: { id: "a1" }, credential: { secret: "s3" } };
		const { api, sent } = setup({ status: 201, body: created });
		const r = await api.agents.register({ name: "bot", scope: ["read"] });
		expect(sent().init.method).toBe("POST");
		expect(sent().body).toEqual({ name: "bot", scope: ["read"] });
		expect(r).toEqual({ success: true, data: created });
	});

	it("revokes with an encoded reason", async () => {
		const { api, sent } = setup({ status: 204 });
		await api.agents.revoke("a1", "no longer used");
		expect(sent().url).toBe("/auth/account/agents/a1?reason=no%20longer%20used");
		expect(sent().init.method).toBe("DELETE");
	});

	it("surfaces 404 when AccountUX is off", async () => {
		const { api } = setup({ status: 404, body: "404 page not found" });
		const r = await api.agents.list();
		expect(r.success).toBe(false);
		if (!r.success) expect(r.error.status).toBe(404);
	});
});

describe("delegations", () => {
	it("unwraps the list", async () => {
		const { api, sent } = setup({ status: 200, body: { delegations: [{ id: "g1" }] } });
		const r = await api.delegations.list();
		expect(sent().url).toBe("/auth/account/delegations");
		expect(r).toEqual({ success: true, data: [{ id: "g1" }] });
	});

	it("grants", async () => {
		const input = {
			agentId: "a1",
			scope: ["read"],
			resource: "https://api",
			maxDurationSeconds: 60,
		};
		const { api, sent } = setup({ status: 201, body: { id: "g1", ...input } });
		const r = await api.delegations.grant(input);
		expect(sent().body).toEqual(input);
		expect(r.success).toBe(true);
	});

	it("revokes with POST", async () => {
		const { api, sent } = setup({ status: 204 });
		await api.delegations.revoke("g1");
		expect(sent().url).toBe("/auth/account/delegations/g1/revoke");
		expect(sent().init.method).toBe("POST");
	});
});
