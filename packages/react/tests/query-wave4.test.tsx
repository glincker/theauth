import { createTheAuthGoClient } from "@glinr/theauth-client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { act } from "react";
import { createRoot } from "react-dom/client";
import { describe, expect, it, vi } from "vitest";
import {
	TheAuthQueryProvider,
	useAgents,
	useCurrentToken,
	useDelegations,
} from "../src/query/index.js";

interface Reply {
	status: number;
	body?: unknown;
}

function route(table: Record<string, Reply>) {
	return vi.fn(async (url: string, init: RequestInit) => {
		const r = table[`${init.method} ${url}`] ?? { status: 404, body: "nope" };
		const text = r.body === undefined ? "" : JSON.stringify(r.body);
		return {
			ok: r.status < 300,
			status: r.status,
			headers: new Headers(),
			text: () => Promise.resolve(text),
		};
	});
}

async function mount<T>(hook: () => T, fetchFn: ReturnType<typeof route>) {
	const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
	const client = createTheAuthGoClient({
		fetch: fetchFn as unknown as typeof fetch,
		getToken: () => "tk",
	});
	const result: { current: T } = { current: undefined as T };
	function Probe() {
		result.current = hook();
		return null;
	}
	const wrapper = (children: ReactNode) => (
		<QueryClientProvider client={qc}>
			<TheAuthQueryProvider client={client}>{children}</TheAuthQueryProvider>
		</QueryClientProvider>
	);
	const root = createRoot(document.createElement("div"));
	await act(async () => {
		root.render(wrapper(<Probe />));
	});
	return { result };
}

const flush = () =>
	act(async () => {
		await new Promise((r) => setTimeout(r, 0));
	});

const calls = (fetchFn: ReturnType<typeof route>) =>
	fetchFn.mock.calls.map(([url, init]) => `${init.method} ${url}`);

describe("useCurrentToken", () => {
	it("loads the token and drops it after revoking", async () => {
		const fetchFn = route({
			"GET /auth/tokens/current": { status: 200, body: { id: "t1", abilities: [] } },
			"DELETE /auth/tokens/current": { status: 204 },
		});
		const { result } = await mount(useCurrentToken, fetchFn);
		await flush();
		expect(result.current.current.data).toMatchObject({ id: "t1" });
		await act(async () => {
			await result.current.revoke.mutateAsync();
		});
		await flush();
		expect(calls(fetchFn)).toContain("DELETE /auth/tokens/current");
	});

	it("exposes only the error code on bearer_required", async () => {
		const fetchFn = route({
			"GET /auth/tokens/current": {
				status: 403,
				body: { code: "auth.bearer_required", message: "m" },
			},
		});
		const { result } = await mount(useCurrentToken, fetchFn);
		await flush();
		expect(result.current.current.error).toMatchObject({
			code: "auth.bearer_required",
			status: 403,
		});
	});
});

describe("useAgents", () => {
	it("lists, registers and refetches, revokes", async () => {
		const fetchFn = route({
			"GET /auth/account/agents": { status: 200, body: { agents: [{ id: "a1" }] } },
			"GET /auth/account/delegations": { status: 200, body: { delegations: [] } },
			"POST /auth/account/agents": {
				status: 201,
				body: { agent: { id: "a2" }, credential: { secret: "s" } },
			},
			"DELETE /auth/account/agents/a1?reason=gone": { status: 204 },
		});
		const { result } = await mount(useAgents, fetchFn);
		await flush();
		expect(result.current.list.data).toEqual([{ id: "a1" }]);
		await act(async () => {
			await result.current.register.mutateAsync({ name: "bot" });
		});
		await flush();
		expect(result.current.register.data?.credential.secret).toBe("s");
		expect(calls(fetchFn).filter((c) => c === "GET /auth/account/agents")).toHaveLength(2);
		await act(async () => {
			await result.current.revoke.mutateAsync({ id: "a1", reason: "gone" });
		});
		await flush();
		expect(calls(fetchFn)).toContain("DELETE /auth/account/agents/a1?reason=gone");
	});
});

describe("useDelegations", () => {
	it("grants and revokes then refetches", async () => {
		const fetchFn = route({
			"GET /auth/account/delegations": { status: 200, body: { delegations: [{ id: "g1" }] } },
			"POST /auth/account/delegations": { status: 201, body: { id: "g2" } },
			"POST /auth/account/delegations/g1/revoke": { status: 204 },
		});
		const { result } = await mount(useDelegations, fetchFn);
		await flush();
		expect(result.current.list.data).toEqual([{ id: "g1" }]);
		await act(async () => {
			await result.current.grant.mutateAsync({
				agentId: "a1",
				scope: ["read"],
				resource: "r",
				maxDurationSeconds: 60,
			});
			await result.current.revoke.mutateAsync({ id: "g1" });
		});
		await flush();
		expect(calls(fetchFn).filter((c) => c === "GET /auth/account/delegations")).toHaveLength(3);
	});
});
