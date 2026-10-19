import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { EventTargetLike } from "../src/refetch.js";
import { attachRefetch } from "../src/refetch.js";
import type { SessionStorageLike } from "../src/session-store.js";
import { createSessionStore } from "../src/session-store.js";

class FakeTarget implements EventTargetLike {
	visibilityState = "visible";
	private map = new Map<string, Set<() => void>>();
	addEventListener(type: string, fn: () => void): void {
		if (!this.map.has(type)) this.map.set(type, new Set());
		this.map.get(type)?.add(fn);
	}
	removeEventListener(type: string, fn: () => void): void {
		this.map.get(type)?.delete(fn);
	}
	emit(type: string): void {
		for (const fn of [...(this.map.get(type) ?? [])]) fn();
	}
	count(): number {
		let n = 0;
		for (const set of this.map.values()) n += set.size;
		return n;
	}
}

function memoryStorage(initial?: string): SessionStorageLike & { raw(): string | null } {
	let value: string | null = initial ?? null;
	return {
		getItem: () => value,
		setItem: (_k, v) => {
			value = v;
		},
		removeItem: () => {
			value = null;
		},
		raw: () => value,
	};
}

const json = (status: number, body: unknown): Response =>
	new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

describe("attachRefetch", () => {
	beforeEach(() => vi.useFakeTimers());
	afterEach(() => vi.useRealTimers());

	it("fires on focus, visible tab and online, not on a hidden tab", () => {
		const win = new FakeTarget();
		const doc = new FakeTarget();
		const trigger = vi.fn();
		attachRefetch(trigger, { env: { window: win, document: doc } });
		win.emit("focus");
		win.emit("online");
		doc.emit("visibilitychange");
		expect(trigger).toHaveBeenCalledTimes(3);
		doc.visibilityState = "hidden";
		doc.emit("visibilitychange");
		expect(trigger).toHaveBeenCalledTimes(3);
	});

	it("honors onFocus and onReconnect opt outs", () => {
		const win = new FakeTarget();
		const doc = new FakeTarget();
		const trigger = vi.fn();
		attachRefetch(trigger, {
			onFocus: false,
			onReconnect: false,
			env: { window: win, document: doc },
		});
		expect(win.count() + doc.count()).toBe(0);
	});

	it("runs the interval, skips it offline, and stop clears everything", () => {
		const win = new FakeTarget();
		const doc = new FakeTarget();
		let online = true;
		const trigger = vi.fn();
		const stop = attachRefetch(trigger, {
			intervalMs: 1000,
			env: { window: win, document: doc, isOnline: () => online },
		});
		vi.advanceTimersByTime(3000);
		expect(trigger).toHaveBeenCalledTimes(3);
		online = false;
		vi.advanceTimersByTime(2000);
		expect(trigger).toHaveBeenCalledTimes(3);
		stop();
		stop();
		online = true;
		vi.advanceTimersByTime(5000);
		win.emit("focus");
		expect(trigger).toHaveBeenCalledTimes(3);
		expect(win.count() + doc.count()).toBe(0);
		expect(vi.getTimerCount()).toBe(0);
	});

	it("keeps the interval offline when whenOffline is set", () => {
		const trigger = vi.fn();
		attachRefetch(trigger, {
			intervalMs: 1000,
			whenOffline: true,
			env: { window: new FakeTarget(), isOnline: () => false },
		});
		vi.advanceTimersByTime(2000);
		expect(trigger).toHaveBeenCalledTimes(2);
	});

	it("is a no-op without a window (server and edge runtimes)", () => {
		expect(typeof (globalThis as { window?: unknown }).window).toBe("undefined");
		const trigger = vi.fn();
		const stop = attachRefetch(trigger, { intervalMs: 10 });
		vi.advanceTimersByTime(100);
		expect(trigger).not.toHaveBeenCalled();
		expect(vi.getTimerCount()).toBe(0);
		expect(() => stop()).not.toThrow();
	});
});

describe("createSessionStore server session", () => {
	const user = { id: "u1", username: "ada@example.com", name: "Ada" };

	it("refresh reads GET /auth/session with the stored bearer token", async () => {
		const storage = memoryStorage(
			JSON.stringify({ token: "tok-1", user: { id: "u1" }, expiresAt: "2999-01-01T00:00:00Z" }),
		);
		const fetchMock = vi.fn(async () =>
			json(200, { user, session: { id: "s1", expiresAt: "2999-02-02T00:00:00Z" } }),
		);
		const store = createSessionStore({ storage, fetch: fetchMock as unknown as typeof fetch });
		await store.refresh();
		const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
		expect(url).toBe("/api/theauth/auth/session");
		expect(init.headers).toEqual({ Authorization: "Bearer tok-1" });
		expect(init.credentials).toBe("include");
		expect(store.getState()).toEqual({
			isLoading: false,
			session: {
				token: "tok-1",
				user: { id: "u1", email: "ada@example.com", name: "Ada", image: undefined },
				expiresAt: "2999-02-02T00:00:00Z",
			},
		});
	});

	it("works for cookie only sessions and does not store an empty token", async () => {
		const storage = memoryStorage();
		const store = createSessionStore({
			storage,
			fetch: (async () => json(200, { user })) as unknown as typeof fetch,
		});
		await store.refresh();
		expect(store.getState().session?.user.id).toBe("u1");
		expect(storage.raw()).toBeNull();
	});

	it("clears the stored session on 401 but keeps it on 500 and network errors", async () => {
		const stored = JSON.stringify({ token: "t", user: { id: "u1" } });
		const storage = memoryStorage(stored);
		let mode: "500" | "net" | "401" = "500";
		const store = createSessionStore({
			storage,
			fetch: (async () => {
				if (mode === "net") throw new TypeError("offline");
				return json(mode === "500" ? 500 : 401, { error: "x" });
			}) as unknown as typeof fetch,
		});
		await store.refresh();
		expect(store.getState().session?.token).toBe("t");
		mode = "net";
		await store.refresh();
		expect(store.getState().session?.token).toBe("t");
		expect(storage.raw()).toBe(stored);
		mode = "401";
		await store.refresh();
		expect(store.getState().session).toBeNull();
		expect(storage.raw()).toBeNull();
	});

	it("dedupes concurrent refreshes into one request", async () => {
		let resolve: (r: Response) => void = () => {};
		const fetchMock = vi.fn(
			() =>
				new Promise<Response>((r) => {
					resolve = r;
				}),
		);
		const store = createSessionStore({ fetch: fetchMock as unknown as typeof fetch });
		const a = store.refresh();
		const b = store.refresh();
		expect(a).toBe(b);
		resolve(json(200, { user }));
		await a;
		expect(fetchMock).toHaveBeenCalledTimes(1);
		const c = store.refresh();
		resolve(json(200, { user }));
		await c;
		expect(fetchMock).toHaveBeenCalledTimes(2);
	});

	it("destroy aborts an in-flight refresh and its late answer is ignored", async () => {
		let signal: AbortSignal | null | undefined;
		const fetchMock = vi.fn((_u: string, init?: RequestInit) => {
			signal = init?.signal;
			return new Promise<Response>((_res, rej) => {
				init?.signal?.addEventListener("abort", () =>
					rej(new DOMException("aborted", "AbortError")),
				);
			});
		});
		const store = createSessionStore({ fetch: fetchMock as unknown as typeof fetch });
		const p = store.refresh();
		store.destroy();
		await p;
		expect(signal?.aborted).toBe(true);
		expect(store.getState()).toEqual({ session: null, isLoading: false });
	});

	it("a sign-out during a refresh wins over the refresh result", async () => {
		let resolve: (r: Response) => void = () => {};
		const calls: string[] = [];
		const store = createSessionStore({
			fetch: ((u: string) => {
				calls.push(u);
				if (u.endsWith("/auth/session"))
					return new Promise<Response>((r) => {
						resolve = r;
					});
				return Promise.resolve(json(200, { success: true }));
			}) as unknown as typeof fetch,
		});
		const p = store.refresh();
		await store.signOut();
		resolve(json(200, { user }));
		await p;
		expect(store.getState().session).toBeNull();
	});

	it("signOut revokes on the server with the bearer token and clears locally", async () => {
		const storage = memoryStorage(JSON.stringify({ token: "tok-9", user: { id: "u1" } }));
		const fetchMock = vi.fn(async () => json(200, { success: true }));
		const store = createSessionStore({ storage, fetch: fetchMock as unknown as typeof fetch });
		store.hydrateSession({ token: "tok-9", user: { id: "u1" } });
		const result = await store.signOut();
		const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
		expect(url).toBe("/api/theauth/auth/sign-out");
		expect(init.method).toBe("POST");
		expect(init.headers).toEqual({ Authorization: "Bearer tok-9" });
		expect(result).toEqual({ success: true });
		expect(storage.raw()).toBeNull();
		expect(store.getState().session).toBeNull();
	});

	it("signOut clears locally even when the server call fails, and says so", async () => {
		const store = createSessionStore({
			fetch: (async () => {
				throw new TypeError("offline");
			}) as unknown as typeof fetch,
		});
		store.hydrateSession({ token: "t", user: { id: "u1" } });
		const result = await store.signOut();
		expect(result).toEqual({ success: false, error: "offline" });
		expect(store.getState().session).toBeNull();
	});

	it("signIn posts to the username route and parses the real response and error shapes", async () => {
		const fetchMock = vi
			.fn()
			.mockResolvedValueOnce(json(401, { error: "Invalid username or password" }))
			.mockResolvedValueOnce(
				json(200, {
					user: { id: "u1", username: "ada" },
					session: { token: "tok", expiresAt: "2999-01-01T00:00:00Z" },
				}),
			);
		const store = createSessionStore({ fetch: fetchMock as unknown as typeof fetch });
		expect(await store.signIn("ada", "bad")).toEqual({
			success: false,
			error: "Invalid username or password",
		});
		expect(await store.signIn("ada", "good")).toEqual({ success: true });
		const [url, init] = fetchMock.mock.calls[1] as unknown as [string, RequestInit];
		expect(url).toBe("/api/theauth/auth/username/sign-in");
		expect(JSON.parse(String(init.body))).toEqual({ username: "ada", password: "good" });
		expect(store.getState().session?.token).toBe("tok");
	});

	it("signUp posts to the username sign-up route", async () => {
		const fetchMock = vi.fn(async () =>
			json(201, {
				user: { id: "u2", username: "bob", name: null },
				session: { token: "t2", expiresAt: "2999-01-01T00:00:00Z" },
			}),
		);
		const store = createSessionStore({ fetch: fetchMock as unknown as typeof fetch });
		expect(await store.signUp("bob", "pw", "Bob")).toEqual({ success: true });
		const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
		expect(url).toBe("/api/theauth/auth/username/sign-up");
		expect(JSON.parse(String(init.body))).toEqual({ username: "bob", password: "pw", name: "Bob" });
	});
});

describe("hydrateSession and auto refetch", () => {
	beforeEach(() => vi.useFakeTimers());
	afterEach(() => vi.useRealTimers());

	it("hydrates without any request, treats expired and malformed input as none", () => {
		const fetchMock = vi.fn();
		const store = createSessionStore({ fetch: fetchMock as unknown as typeof fetch });
		store.hydrateSession({ user: { id: "u1" }, expiresAt: "2999-01-01T00:00:00Z" });
		expect(store.getState()).toEqual({
			isLoading: false,
			session: {
				token: "",
				user: { id: "u1", email: undefined, name: undefined, image: undefined },
				expiresAt: "2999-01-01T00:00:00Z",
			},
		});
		store.hydrateSession({ user: { id: "u1" }, expiresAt: "2000-01-01T00:00:00Z" });
		expect(store.getState().session).toBeNull();
		store.hydrateSession({ user: {} as { id: string } });
		expect(store.getState().session).toBeNull();
		store.hydrateSession(null);
		expect(store.getState()).toEqual({ session: null, isLoading: false });
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("refetches on focus while subscribed and detaches after the last unsubscribe", async () => {
		const win = new FakeTarget();
		const doc = new FakeTarget();
		const fetchMock = vi.fn(async () => json(200, { user: { id: "u1" } }));
		const store = createSessionStore({
			fetch: fetchMock as unknown as typeof fetch,
			refetch: { intervalMs: 5000, env: { window: win, document: doc } },
		});
		expect(win.count()).toBe(0);
		const off = store.subscribe(() => {});
		const off2 = store.subscribe(() => {});
		win.emit("focus");
		doc.emit("visibilitychange");
		await vi.advanceTimersByTimeAsync(0);
		expect(fetchMock).toHaveBeenCalledTimes(1);
		await vi.advanceTimersByTimeAsync(5000);
		expect(fetchMock).toHaveBeenCalledTimes(2);
		off();
		expect(win.count()).toBeGreaterThan(0);
		off2();
		expect(win.count() + doc.count()).toBe(0);
		expect(vi.getTimerCount()).toBe(0);
	});

	it("does not attach anything on a server with no window", () => {
		const store = createSessionStore({ refetch: { intervalMs: 100 } });
		const off = store.subscribe(() => {});
		expect(vi.getTimerCount()).toBe(0);
		off();
	});
});
