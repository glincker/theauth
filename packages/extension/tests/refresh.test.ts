import { describe, expect, it } from "vitest";
import { createExtensionAuth, ExtensionAuthError } from "../src/index.js";
import type { FakeServer } from "./helpers.js";
import { baseOptions, fakeServer, fakeStorage, tokenCalls, tokenJson } from "./helpers.js";

function refreshCalls(server: FakeServer) {
	return tokenCalls(server).filter((c) => c.params.get("grant_type") === "refresh_token");
}

/** Gate that lets a test hold a token response open. */
function gate() {
	let open: () => void = () => undefined;
	const promise = new Promise<void>((resolve) => {
		open = resolve;
	});
	return { promise, open };
}

describe("refresh", () => {
	it("is single flight for two concurrent callers", async () => {
		const server = fakeServer();
		const storage = fakeStorage();
		let now = 1_000_000;
		const auth = createExtensionAuth(baseOptions(server, storage, { clock: () => now }));
		await auth.signIn();
		now += 3_600_000;

		const g = gate();
		server.onToken = async (call) => {
			if (call.params.get("grant_type") === "refresh_token") await g.promise;
			return tokenJson({ access_token: "at-2", refresh_token: "rt-2", expires_in: 3600 });
		};
		const a = auth.getAccessToken();
		const b = auth.getAccessToken();
		g.open();
		expect(await Promise.all([a, b])).toEqual(["at-2", "at-2"]);
		expect(refreshCalls(server)).toHaveLength(1);
		expect(refreshCalls(server)[0]?.params.get("refresh_token")).toBe("rt-1");
	});

	it("is single flight across a worker restart (new instance, same storage)", async () => {
		const server = fakeServer();
		const storage = fakeStorage();
		let now = 1_000_000;
		const options = () => baseOptions(server, storage, { clock: () => now });
		await createExtensionAuth(options()).signIn();
		now += 3_600_000;

		const g = gate();
		server.onToken = async (call) => {
			if (call.params.get("grant_type") === "refresh_token") await g.promise;
			return tokenJson({ access_token: "at-2", refresh_token: "rt-2" });
		};
		const first = createExtensionAuth(options());
		const second = createExtensionAuth(options());
		const a = first.getAccessToken();
		// Let the first worker claim the lock before the second wakes up.
		await new Promise((r) => setTimeout(r, 20));
		const b = second.getAccessToken();
		await new Promise((r) => setTimeout(r, 20));
		g.open();
		expect(await Promise.all([a, b])).toEqual(["at-2", "at-2"]);
		expect(refreshCalls(server)).toHaveLength(1);
	});

	it("rehydrates from storage with no network call while the token is fresh", async () => {
		const server = fakeServer();
		const storage = fakeStorage();
		await createExtensionAuth(baseOptions(server, storage)).signIn();
		const before = server.calls.length;
		const restarted = createExtensionAuth(baseOptions(server, storage));
		expect(await restarted.getAccessToken()).toBe("at-1");
		expect(server.calls.length).toBe(before);
	});

	it("refreshes inside the skew window", async () => {
		const server = fakeServer();
		const storage = fakeStorage();
		let now = 0;
		const auth = createExtensionAuth(
			baseOptions(server, storage, { clock: () => now, refreshSkewSeconds: 120 }),
		);
		await auth.signIn();
		now = 3_600_000 - 90_000;
		server.onToken = () => tokenJson({ access_token: "at-2" });
		expect(await auth.getAccessToken()).toBe("at-2");
	});

	it("keeps the old refresh token when the server does not rotate it", async () => {
		const server = fakeServer();
		const storage = fakeStorage();
		let now = 0;
		const auth = createExtensionAuth(baseOptions(server, storage, { clock: () => now }));
		await auth.signIn();
		server.onToken = () => tokenJson({ access_token: "at-2", refresh_token: undefined });
		now = 4_000_000;
		await auth.getAccessToken();
		now = 8_000_000;
		await auth.getAccessToken();
		expect(refreshCalls(server).map((c) => c.params.get("refresh_token"))).toEqual([
			"rt-1",
			"rt-1",
		]);
	});

	it("clears state and emits signed out on invalid_grant", async () => {
		const server = fakeServer();
		const storage = fakeStorage();
		let now = 0;
		const auth = createExtensionAuth(baseOptions(server, storage, { clock: () => now }));
		await auth.signIn();
		const seen: Array<unknown> = [];
		auth.onChange((s) => seen.push(s));
		server.onToken = () => Response.json({ error: "invalid_grant" }, { status: 400 });
		now = 4_000_000;

		await expect(auth.getAccessToken()).rejects.toMatchObject({ code: "refresh_failed" });
		expect(seen).toEqual([null]);
		expect(await storage.local.get("theauth:ext:ext-client:refresh")).toEqual({});
		expect(await storage.session.get("theauth:ext:ext-client:access")).toEqual({});
		expect(await auth.getSession()).toBeNull();
		await expect(auth.getAccessToken()).rejects.toMatchObject({ code: "not_signed_in" });
	});

	it("keeps state on a transient failure", async () => {
		const server = fakeServer();
		const storage = fakeStorage();
		let now = 0;
		const auth = createExtensionAuth(baseOptions(server, storage, { clock: () => now }));
		await auth.signIn();
		server.onToken = () => new Response("down", { status: 503 });
		now = 4_000_000;
		await expect(auth.getAccessToken()).rejects.toBeInstanceOf(ExtensionAuthError);
		server.onToken = () => tokenJson({ access_token: "at-3" });
		expect(await auth.getAccessToken()).toBe("at-3");
	});

	it("revokes on sign out and clears storage", async () => {
		const server = fakeServer();
		const storage = fakeStorage();
		const auth = createExtensionAuth(baseOptions(server, storage));
		await auth.signIn();
		const seen: Array<unknown> = [];
		auth.onChange((s) => seen.push(s));
		expect(await auth.signOut()).toEqual({ revoked: true });
		const revoke = server.calls.find((c) => c.url.endsWith("/revoke"));
		expect(revoke?.params.get("token")).toBe("rt-1");
		expect(revoke?.params.get("token_type_hint")).toBe("refresh_token");
		expect(seen).toEqual([null]);
		expect(await auth.getSession()).toBeNull();
	});
});
