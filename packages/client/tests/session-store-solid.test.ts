import { describe, expect, it, vi } from "vitest";
import type { SessionStorageLike } from "../src/index.js";
import { createSessionStore, createSolidAuth } from "../src/index.js";

function memoryStorage(): SessionStorageLike {
	const m = new Map<string, string>();
	return {
		getItem: (k) => m.get(k) ?? null,
		setItem: (k, v) => void m.set(k, v),
		removeItem: (k) => void m.delete(k),
	};
}

function json(status: number, body: unknown): Response {
	return new Response(JSON.stringify(body), { status });
}

describe("createSessionStore", () => {
	it("signs in, persists, notifies, and signs out", async () => {
		const storage = memoryStorage();
		const fetchMock = vi.fn(async () =>
			json(200, { user: { id: "u1", email: "a@b.c" }, session: { token: "t", expiresAt: "x" } }),
		);
		const store = createSessionStore({ storage, fetch: fetchMock as unknown as typeof fetch });
		const seen: Array<string | null> = [];
		store.subscribe((s) => seen.push(s.session?.token ?? null));
		expect(await store.signIn("a@b.c", "pw")).toEqual({ success: true });
		expect(fetchMock.mock.calls[0]?.[0]).toBe("/api/theauth/auth/username/sign-in");
		expect(storage.getItem("theauth_session")).toContain('"token":"t"');
		await store.signOut();
		expect(seen).toEqual(["t", null]);
		expect(storage.getItem("theauth_session")).toBeNull();
	});

	it("returns the server error message and survives network failure", async () => {
		const bad = createSessionStore({
			fetch: (async () => json(401, { error: { message: "Bad credentials" } })) as typeof fetch,
		});
		expect(await bad.signIn("a", "b")).toEqual({ success: false, error: "Bad credentials" });
		const down = createSessionStore({
			fetch: (async () => {
				throw new Error("offline");
			}) as typeof fetch,
		});
		expect(await down.signUp("a", "b")).toEqual({ success: false, error: "offline" });
	});

	it("refresh restores a stored session while the server is unreachable", async () => {
		const storage = memoryStorage();
		storage.setItem("theauth_session", JSON.stringify({ token: "t", user: { id: "u" } }));
		const store = createSessionStore({
			storage,
			fetch: (async () => {
				throw new TypeError("offline");
			}) as typeof fetch,
		});
		await store.refresh();
		expect(store.getState().session?.user.id).toBe("u");
		expect(store.getState().isLoading).toBe(false);
	});

	it("refresh ignores corrupt stored data", async () => {
		const storage = memoryStorage();
		storage.setItem("theauth_session", "{nope");
		const store = createSessionStore({
			storage,
			fetch: (async () => json(401, { error: "Not authenticated" })) as typeof fetch,
		});
		await store.refresh();
		expect(store.getState().session).toBeNull();
	});
});

describe("createSolidAuth", () => {
	it("backs accessors with signals and unsubscribes on cleanup", async () => {
		let cleanup: (() => void) | undefined;
		const solid = {
			createSignal<T>(v: T): [() => T, (n: T) => void] {
				let value = v;
				return [
					() => value,
					(n) => {
						value = n;
					},
				];
			},
			onCleanup(fn: () => void) {
				cleanup = fn;
			},
		};
		const storage = memoryStorage();
		storage.setItem("theauth_session", JSON.stringify({ token: "t", user: { id: "u9" } }));
		const store = createSessionStore({
			storage,
			fetch: (async () => json(200, { success: true })) as typeof fetch,
		});
		const auth = createSolidAuth(solid, store);
		const user = auth.useUser();
		expect(user()).toBeNull();
		void store.refresh();
		expect(user()?.id).toBe("u9");
		cleanup?.();
		await store.signOut();
		expect(user()?.id).toBe("u9");
	});
});
