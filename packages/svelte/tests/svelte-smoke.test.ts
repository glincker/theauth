import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { createAgentStore, createTheAuthClient } from "../src/index.js";
import type { TheAuthSession } from "../src/types.js";

const SESSION_KEY = "theauth_session";

const restoredSession = {
	token: "session-token-1",
	user: {
		id: "user-1",
		email: "ada@example.com",
		name: "Ada",
	},
	expiresAt: "2026-03-30T00:00:00.000Z",
};

const existingAgent = {
	id: "agent-1",
	ownerId: "user-1",
	name: "Existing Agent",
	type: "service" as const,
	token: "agent-token-1",
	permissions: [],
	status: "active" as const,
	expiresAt: null,
	createdAt: "2026-03-29T12:00:00.000Z",
	updatedAt: "2026-03-29T12:00:00.000Z",
};

const createdAgent = {
	id: "agent-2",
	ownerId: "user-1",
	name: "Created Agent",
	type: "service" as const,
	token: "agent-token-2",
	permissions: [],
	status: "active" as const,
	expiresAt: null,
	createdAt: "2026-03-29T12:05:00.000Z",
	updatedAt: "2026-03-29T12:05:00.000Z",
};

function flush(): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, 0));
}

async function waitFor(predicate: () => boolean): Promise<void> {
	for (let i = 0; i < 20; i += 1) {
		if (predicate()) return;
		await flush();
	}
	throw new Error("timed out waiting for state");
}

function installMockLocalStorage() {
	const store = new Map<string, string>();
	const mockStorage = {
		getItem(key: string) {
			return store.get(key) ?? null;
		},
		setItem(key: string, value: string) {
			store.set(key, value);
		},
		removeItem(key: string) {
			store.delete(key);
		},
		clear() {
			store.clear();
		},
	};

	Object.defineProperty(window, "localStorage", {
		value: mockStorage,
		configurable: true,
	});
	Object.defineProperty(globalThis, "localStorage", {
		value: mockStorage,
		configurable: true,
	});
}

beforeEach(() => {
	installMockLocalStorage();
	window.localStorage.clear();
	document.body.innerHTML = "";
	vi.stubGlobal(
		"fetch",
		vi.fn(async () => ({
			ok: true,
			status: 200,
			json: async () => ({}),
		})) as typeof fetch,
	);
});

afterEach(() => {
	vi.unstubAllGlobals();
	document.body.innerHTML = "";
	window.localStorage.clear();
});

test("restores a stored session and clears it on sign out", async () => {
	window.localStorage.setItem(SESSION_KEY, JSON.stringify(restoredSession));

	const client = createTheAuthClient({ basePath: "/api/theauth" });
	let sessionValue: TheAuthSession | null = null;
	let isLoading = true;

	const unsubscribeSession = client.session.subscribe((value) => {
		sessionValue = value;
	});
	const unsubscribeLoading = client.isLoading.subscribe((value) => {
		isLoading = value;
	});

	await waitFor(() => sessionValue !== null);
	// The stored session shows at once, then the server read settles the loading flag.
	await waitFor(() => !isLoading);

	expect(sessionValue).toMatchObject(restoredSession);
	expect(isLoading).toBe(false);

	await client.signOut();
	await waitFor(() => sessionValue === null);

	expect(window.localStorage.getItem(SESSION_KEY)).toBeNull();

	unsubscribeSession();
	unsubscribeLoading();
});

test("auto-loads agents after sign-in and refreshes them after create", async () => {
	let signInCalls = 0;
	let agentListCalls = 0;
	const signInResponse = {
		user: restoredSession.user,
		session: {
			token: restoredSession.token,
			expiresAt: restoredSession.expiresAt,
		},
	};

	vi.stubGlobal(
		"fetch",
		vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
			const url = new URL(String(input), "http://localhost");
			const method = init?.method ?? "GET";

			if (url.pathname === "/api/theauth/auth/username/sign-in") {
				signInCalls += 1;
				return {
					ok: true,
					status: 200,
					json: async () => signInResponse,
				};
			}

			if (url.pathname === "/api/theauth/agents" && method === "GET") {
				agentListCalls += 1;
				return {
					ok: true,
					status: 200,
					json: async () => ({
						data: agentListCalls === 1 ? [existingAgent] : [existingAgent, createdAgent],
					}),
				};
			}

			if (url.pathname === "/api/theauth/agents" && method === "POST") {
				return {
					ok: true,
					status: 200,
					json: async () => ({
						data: createdAgent,
					}),
				};
			}

			throw new Error(`unexpected request: ${method} ${url.pathname}`);
		}) as typeof fetch,
	);

	const client = createTheAuthClient({ basePath: "/api/theauth" });
	const agentStore = createAgentStore({ user: client.user });

	let sessionValue = null as unknown;
	let agentsValue: Array<typeof existingAgent> = [];

	const unsubscribeSession = client.session.subscribe((value) => {
		sessionValue = value;
	});
	const unsubscribeAgents = agentStore.agents.subscribe((value) => {
		agentsValue = value;
	});

	const signInResult = await client.signIn("ada@example.com", "secret");
	expect(signInResult).toEqual({ success: true, data: undefined });
	expect(signInCalls).toBe(1);

	await waitFor(() => sessionValue !== null);
	await waitFor(() => agentsValue.length === 1);

	expect(agentsValue).toEqual([existingAgent]);

	const createResult = await agentStore.create({
		ownerId: "user-1",
		name: "Created Agent",
		type: "service",
		permissions: [],
	});

	expect(createResult).toEqual({ success: true, data: createdAgent });
	await waitFor(() => agentsValue.length === 2);
	expect(agentsValue).toEqual([existingAgent, createdAgent]);

	unsubscribeSession();
	unsubscribeAgents();
});

test("signOut revokes the session on the server with the stored token", async () => {
	window.localStorage.setItem(SESSION_KEY, JSON.stringify(restoredSession));
	const calls: Array<{ path: string; auth: string | null }> = [];
	vi.stubGlobal(
		"fetch",
		vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
			const path = new URL(String(input), "http://localhost").pathname;
			calls.push({ path, auth: new Headers(init?.headers).get("authorization") });
			return { ok: true, status: 200, json: async () => ({ success: true }) };
		}) as typeof fetch,
	);
	const client = createTheAuthClient();
	let sessionValue: TheAuthSession | null = null;
	const off = client.session.subscribe((v) => {
		sessionValue = v;
	});
	await waitFor(() => sessionValue !== null);
	await client.signOut();
	expect(calls.at(-1)).toEqual({
		path: "/api/theauth/auth/sign-out",
		auth: `Bearer ${restoredSession.token}`,
	});
	expect(sessionValue).toBeNull();
	expect(window.localStorage.getItem(SESSION_KEY)).toBeNull();
	off();
});

test("reads the session from the server when nothing is stored", async () => {
	vi.stubGlobal(
		"fetch",
		vi.fn(async () => ({
			ok: true,
			status: 200,
			json: async () => ({ user: { id: "user-7", username: "lee" }, session: { id: "s" } }),
		})) as typeof fetch,
	);
	const client = createTheAuthClient();
	let sessionValue: TheAuthSession | null = null;
	const off = client.session.subscribe((v) => {
		sessionValue = v;
	});
	await waitFor(() => sessionValue !== null);
	expect((sessionValue as TheAuthSession | null)?.user.id).toBe("user-7");
	off();
});

test("initialSession hydrates with no request, and focus refetches only while subscribed", async () => {
	const fetchMock = vi.fn(async () => ({
		ok: true,
		status: 200,
		json: async () => ({ user: { id: "ssr-1" } }),
	}));
	vi.stubGlobal("fetch", fetchMock as unknown as typeof fetch);
	const client = createTheAuthClient({
		initialSession: { user: { id: "ssr-1" } },
		refetch: { onFocus: true },
	});
	let sessionValue: TheAuthSession | null = null;
	const off = client.session.subscribe((v) => {
		sessionValue = v;
	});
	expect((sessionValue as TheAuthSession | null)?.user.id).toBe("ssr-1");
	expect(fetchMock).not.toHaveBeenCalled();
	window.dispatchEvent(new Event("focus"));
	await flush();
	expect(fetchMock).toHaveBeenCalledTimes(1);
	off();
	window.dispatchEvent(new Event("focus"));
	await flush();
	expect(fetchMock).toHaveBeenCalledTimes(1);
});
