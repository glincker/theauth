import { createTheAuthGoClient } from "@glinr/theauth-client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { act } from "react";
import { createRoot } from "react-dom/client";
import { describe, expect, it, vi } from "vitest";
import {
	authKeys,
	TheAuthQueryProvider,
	useAgentTokens,
	useApiTokens,
	useBootstrapStatus,
	useChangePassword,
	useDeviceApproval,
	usePasskeys,
	useSessions,
	useStepUp,
	useTotp,
	useTotpStatus,
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
	const client = createTheAuthGoClient({ fetch: fetchFn as unknown as typeof fetch });
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
	return { result, qc };
}

const flush = () =>
	act(async () => {
		await new Promise((r) => setTimeout(r, 0));
	});

const calls = (fetchFn: ReturnType<typeof route>) =>
	fetchFn.mock.calls.map(([url, init]) => `${init.method} ${url}`);

describe("useSessions", () => {
	it("lists sessions and refetches after revoking one", async () => {
		const fetchFn = route({
			"GET /auth/sessions": { status: 200, body: { sessions: [{ id: "s1", current: false }] } },
			"GET /auth/me": { status: 200, body: { id: "u1" } },
			"DELETE /auth/sessions/s1": { status: 204 },
			"POST /auth/sessions/revoke-others": { status: 200, body: { revoked: 2 } },
		});
		const { result } = await mount(useSessions, fetchFn);
		await flush();
		expect(result.current.list.data).toEqual([{ id: "s1", current: false }]);
		await act(async () => {
			await result.current.revoke.mutateAsync("s1");
		});
		await flush();
		expect(calls(fetchFn).filter((c) => c === "GET /auth/sessions")).toHaveLength(2);
		await act(async () => {
			await result.current.revokeOthers.mutateAsync();
		});
		await flush();
		expect(result.current.revokeOthers.data).toEqual({ revoked: 2 });
	});
});

describe("useStepUp", () => {
	it("returns elevatedUntil on success", async () => {
		const fetchFn = route({
			"POST /auth/step-up": { status: 200, body: { elevatedUntil: "2026-01-01T00:00:00Z" } },
		});
		const { result } = await mount(useStepUp, fetchFn);
		await act(async () => {
			await result.current.verify.mutateAsync({ method: "password", password: "p" });
		});
		await flush();
		expect(result.current.verify.data).toEqual({ elevatedUntil: "2026-01-01T00:00:00Z" });
	});

	it("rejects with the code and retryAfter for a throttle", async () => {
		const fetchFn = vi.fn(async () => ({
			ok: false,
			status: 429,
			headers: new Headers({ "Retry-After": "30" }),
			text: () => Promise.resolve(JSON.stringify({ code: "rate_limited", message: "m" })),
		}));
		const { result } = await mount(useStepUp, fetchFn as unknown as ReturnType<typeof route>);
		await act(async () => {
			await result.current.verify.mutateAsync({ method: "totp", code: "1" }).catch(() => undefined);
		});
		await flush();
		expect(result.current.verify.error).toMatchObject({ message: "rate_limited", retryAfter: 30 });
	});
});

describe("useApiTokens", () => {
	it("lists, mints and revokes with invalidation", async () => {
		const fetchFn = route({
			"GET /auth/tokens/": { status: 200, body: { tokens: [{ id: "t1" }] } },
			"POST /auth/tokens/": { status: 201, body: { token: "raw", id: "t2" } },
			"DELETE /auth/tokens/t1": { status: 204 },
		});
		const { result } = await mount(() => useApiTokens(), fetchFn);
		await flush();
		expect(result.current.list.data).toEqual([{ id: "t1" }]);
		await act(async () => {
			await result.current.mint.mutateAsync({ name: "ci", abilities: [] });
		});
		await flush();
		expect(result.current.mint.data).toMatchObject({ token: "raw" });
		await act(async () => {
			await result.current.revoke.mutateAsync("t1");
		});
		await flush();
		expect(calls(fetchFn).filter((c) => c === "GET /auth/tokens/")).toHaveLength(3);
	});

	it("keys admin filters separately", () => {
		expect(authKeys.apiTokenList({ all: true })).not.toEqual(authKeys.apiTokenList({}));
	});
});

describe("useDeviceApproval", () => {
	it("stays idle without a code", async () => {
		const fetchFn = route({});
		const { result } = await mount(() => useDeviceApproval("  "), fetchFn);
		await flush();
		expect(fetchFn).not.toHaveBeenCalled();
		expect(result.current.info.fetchStatus).toBe("idle");
	});

	it("loads info then approves", async () => {
		const fetchFn = route({
			"POST /auth/device/approve": {
				status: 200,
				body: { client_name: "cli" },
			},
		});
		const { result } = await mount(() => useDeviceApproval("ABCD-1234"), fetchFn);
		await flush();
		expect(result.current.info.data?.clientName).toBe("cli");
		fetchFn.mockClear();
		await act(async () => {
			await result.current.approve.mutateAsync(undefined);
		});
		const body = JSON.parse(fetchFn.mock.calls[0]?.[1].body as string);
		expect(body).toEqual({ action: "approve", user_code: "ABCD-1234" });
	});

	it("surfaces an unknown code as an error code", async () => {
		const fetchFn = route({
			"POST /auth/device/approve": {
				status: 404,
				body: { error: "invalid_user_code", error_description: "x" },
			},
		});
		const { result } = await mount(() => useDeviceApproval("NOPE"), fetchFn);
		await flush();
		expect(result.current.info.error?.message).toBe("invalid_user_code");
	});
});

describe("useBootstrapStatus", () => {
	it("reports needsSetup", async () => {
		const { result } = await mount(
			useBootstrapStatus,
			route({ "GET /auth/bootstrap/status": { status: 200, body: { needsSetup: true } } }),
		);
		await flush();
		expect(result.current.data).toEqual({ needsSetup: true });
	});
});

describe("totp and passkey additions", () => {
	it("refreshes status after regenerating codes", async () => {
		const fetchFn = route({
			"GET /auth/totp/": { status: 200, body: { enrolled: true, recoveryCodesRemaining: 1 } },
			"POST /auth/totp/recovery-codes": { status: 200, body: { recoveryCodes: ["a"] } },
		});
		const { result } = await mount(() => ({ status: useTotpStatus(), totp: useTotp() }), fetchFn);
		await flush();
		expect(result.current.status.data?.recoveryCodesRemaining).toBe(1);
		await act(async () => {
			await result.current.totp.regenerateRecoveryCodes.mutateAsync();
		});
		await flush();
		expect(calls(fetchFn).filter((c) => c === "GET /auth/totp/")).toHaveLength(2);
	});

	it("renames a passkey and refetches", async () => {
		const fetchFn = route({
			"GET /auth/webauthn/credentials": { status: 200, body: [] },
			"PATCH /auth/webauthn/credentials/p1": { status: 204 },
		});
		const { result } = await mount(usePasskeys, fetchFn);
		await flush();
		await act(async () => {
			await result.current.rename.mutateAsync({ id: "p1", name: "Laptop" });
		});
		await flush();
		expect(calls(fetchFn).filter((c) => c === "GET /auth/webauthn/credentials")).toHaveLength(2);
	});
});

describe("useChangePassword", () => {
	it("posts and refreshes sessions", async () => {
		const fetchFn = route({
			"POST /auth/password/change": { status: 204 },
			"GET /auth/sessions": { status: 200, body: { sessions: [] } },
		});
		const { result } = await mount(
			() => ({ change: useChangePassword(), sessions: useSessions() }),
			fetchFn,
		);
		await flush();
		await act(async () => {
			await result.current.change.mutateAsync({ currentPassword: "a", newPassword: "b" });
		});
		await flush();
		expect(calls(fetchFn).filter((c) => c === "GET /auth/sessions")).toHaveLength(2);
	});
});

describe("agent tokens", () => {
	const tokens = [
		{ id: "p1", name: "ci" },
		{ id: "a1", name: "bot", kind: "agent", agentName: "claude", delegatedBy: "u1" },
	];
	it("filters by kind from one shared fetch", async () => {
		const fetchFn = route({ "GET /auth/tokens/": { status: 200, body: { tokens } } });
		const { result } = await mount(() => useApiTokens({ kind: "agent" }), fetchFn);
		await flush();
		expect(result.current.list.data?.map((t) => t.id)).toEqual(["a1"]);
		expect(calls(fetchFn)).toEqual(["GET /auth/tokens/"]);
	});
	it("mints with kind agent and invalidates the list", async () => {
		const fetchFn = route({
			"GET /auth/tokens/": { status: 200, body: { tokens } },
			"POST /auth/tokens/": { status: 201, body: { token: "raw", id: "a2", kind: "agent" } },
			"DELETE /auth/tokens/a1": { status: 204 },
		});
		const { result } = await mount(useAgentTokens, fetchFn);
		await flush();
		await act(async () => {
			await result.current.mint.mutateAsync({ name: "n", abilities: ["a"], agentName: "claude" });
		});
		const post = fetchFn.mock.calls.find(([, i]) => i.method === "POST");
		expect(JSON.parse(String(post?.[1].body))).toEqual({
			name: "n",
			abilities: ["a"],
			agent_name: "claude",
			kind: "agent",
		});
		await act(async () => {
			await result.current.revoke.mutateAsync("a1");
		});
		await flush();
		expect(calls(fetchFn).filter((c) => c === "GET /auth/tokens/").length).toBe(3);
	});
});
