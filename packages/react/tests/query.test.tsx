import { createTheAuthGoClient } from "@glinr/theauth-client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { act } from "react";
import { createRoot } from "react-dom/client";
import { describe, expect, it, vi } from "vitest";
import {
	authKeys,
	TheAuthQueryProvider,
	useLogin,
	usePasskeys,
	useSession,
	useSessions,
	useTotp,
} from "../src/query/index.js";

interface Reply {
	status: number;
	body?: unknown;
}

function route(table: Record<string, Reply>) {
	return vi.fn(async (url: string, init: RequestInit) => {
		const hit = table[`${init.method} ${url}`];
		const r = hit ?? { status: 404, body: "nope" };
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
	return { result, qc, unmount: () => act(async () => root.unmount()) };
}

const flush = () =>
	act(async () => {
		await new Promise((r) => setTimeout(r, 0));
	});

describe("useSession", () => {
	it("returns the user on 200", async () => {
		const { result } = await mount(
			useSession,
			route({ "GET /auth/me": { status: 200, body: { id: "u1" } } }),
		);
		await flush();
		expect(result.current.data).toEqual({ id: "u1" });
	});

	it("returns null on 401", async () => {
		const { result } = await mount(
			useSession,
			route({ "GET /auth/me": { status: 401, body: "unauthorized" } }),
		);
		await flush();
		expect(result.current.data).toBeNull();
		expect(result.current.isError).toBe(false);
	});

	it("surfaces other failures as an error code", async () => {
		const { result } = await mount(
			useSession,
			route({ "GET /auth/me": { status: 500, body: "boom" } }),
		);
		await flush();
		expect(result.current.error?.message).toBe("HTTP_ERROR");
	});
});

describe("useLogin", () => {
	const cases: Array<[string, Reply, unknown]> = [
		["ok", { status: 200, body: { ok: true, step: "full" } }, { status: "ok" }],
		["mfa", { status: 200, body: { step: "totp_required" } }, { status: "mfa_required" }],
	];
	it.each(cases)("resolves %s and invalidates the session", async (_n, reply, expected) => {
		const fetchFn = route({
			"POST /auth/email-password/signin": reply,
			"GET /auth/me": { status: 200, body: { id: "u1" } },
		});
		const { result, qc } = await mount(
			() => ({ login: useLogin(), session: useSession() }),
			fetchFn,
		);
		await flush();
		const spy = vi.spyOn(qc, "invalidateQueries");
		let out: unknown;
		await act(async () => {
			out = await result.current.login.mutateAsync({ email: "a", password: "b" });
		});
		expect(out).toEqual(expected);
		expect(spy).toHaveBeenCalledWith({ queryKey: authKeys.session() });
	});

	it("rejects with a code, not prose", async () => {
		const fetchFn = route({
			"POST /auth/email-password/signin": {
				status: 429,
				body: { code: "RATE_LIMITED", message: "x" },
			},
		});
		const { result } = await mount(useLogin, fetchFn);
		await act(async () => {
			await result.current.mutateAsync({ email: "a", password: "b" }).catch(() => undefined);
		});
		await flush();
		expect(result.current.error).toMatchObject({ message: "RATE_LIMITED", status: 429 });
	});
});

describe("usePasskeys", () => {
	it("lists and removes, refetching after removal", async () => {
		let creds = [{ id: "p1" }];
		const fetchFn = vi.fn(async (_url: string, init: RequestInit) => {
			if (init.method === "DELETE") creds = [];
			const empty = init.method === "DELETE";
			return {
				ok: true,
				status: empty ? 204 : 200,
				headers: new Headers(),
				text: () => Promise.resolve(empty ? "" : JSON.stringify(creds)),
			};
		});
		const { result } = await mount(usePasskeys, fetchFn as unknown as ReturnType<typeof route>);
		await flush();
		expect(result.current.list.data).toEqual([{ id: "p1" }]);
		await act(async () => {
			await result.current.remove.mutateAsync("p1");
		});
		await flush();
		expect(result.current.list.data).toEqual([]);
	});
});

describe("useTotp", () => {
	it("returns recovery codes from enrollFinish", async () => {
		const fetchFn = route({
			"POST /auth/totp/enroll/finish": { status: 200, body: { recoveryCodes: ["r1", "r2"] } },
		});
		const { result } = await mount(useTotp, fetchFn);
		let out: unknown;
		await act(async () => {
			out = await result.current.enrollFinish.mutateAsync({ enrollmentId: "e", code: "123456" });
		});
		expect(out).toEqual({ recoveryCodes: ["r1", "r2"] });
	});
});

describe("useSessions", () => {
	it("exposes the current user and revokes it", async () => {
		const fetchFn = route({
			"GET /auth/me": { status: 200, body: { id: "u1" } },
			"DELETE /auth/sessions/current": { status: 204 },
		});
		const { result } = await mount(useSessions, fetchFn);
		await flush();
		expect(result.current.current.data).toEqual({ id: "u1" });
		await act(async () => {
			await result.current.revokeCurrent.mutateAsync();
		});
		await flush();
		expect(result.current.revokeCurrent.isSuccess).toBe(true);
		expect(fetchFn).toHaveBeenCalledWith(
			"/auth/sessions/current",
			expect.objectContaining({ method: "DELETE" }),
		);
	});
});
