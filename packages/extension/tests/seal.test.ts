import { describe, expect, it } from "vitest";
import { createExtensionAuth, createMemoryKeyStore } from "../src/index.js";
import { baseOptions, fakeServer, fakeStorage, tokenCalls, tokenJson } from "./helpers.js";

const REFRESH_KEY = "theauth:ext:ext-client:refresh";

describe("encryptRefreshToken", () => {
	it("round trips and never stores the plaintext", async () => {
		const server = fakeServer();
		const storage = fakeStorage();
		const keyStore = createMemoryKeyStore();
		let now = 0;
		const options = () =>
			baseOptions(server, storage, { encryptRefreshToken: true, keyStore, clock: () => now });
		await createExtensionAuth(options()).signIn();

		const stored = (await storage.local.get(REFRESH_KEY))[REFRESH_KEY];
		expect(JSON.stringify(stored)).not.toContain("rt-1");
		expect(stored).toMatchObject({ v: 1 });

		// A restarted worker with the same key store can use it.
		now = 4_000_000;
		server.onToken = () => tokenJson({ access_token: "at-2", refresh_token: "rt-2" });
		expect(await createExtensionAuth(options()).getAccessToken()).toBe("at-2");
		const refresh = tokenCalls(server).find((c) => c.params.get("grant_type") === "refresh_token");
		expect(refresh?.params.get("refresh_token")).toBe("rt-1");
	});

	it("rejects a tampered value and sends nothing", async () => {
		const server = fakeServer();
		const storage = fakeStorage();
		const keyStore = createMemoryKeyStore();
		let now = 0;
		const options = () =>
			baseOptions(server, storage, { encryptRefreshToken: true, keyStore, clock: () => now });
		await createExtensionAuth(options()).signIn();

		const stored = (await storage.local.get(REFRESH_KEY))[REFRESH_KEY] as { ct: string };
		const flipped = stored.ct.startsWith("A") ? `B${stored.ct.slice(1)}` : `A${stored.ct.slice(1)}`;
		await storage.local.set({ [REFRESH_KEY]: { ...stored, ct: flipped } });

		now = 4_000_000;
		const before = server.calls.length;
		await expect(createExtensionAuth(options()).getAccessToken()).rejects.toMatchObject({
			code: "refresh_failed",
		});
		expect(server.calls.length).toBe(before);
		expect(await storage.local.get(REFRESH_KEY)).toEqual({});
	});

	it("rejects a plaintext value planted in an encrypted slot", async () => {
		const server = fakeServer();
		const storage = fakeStorage();
		let now = 0;
		const auth = createExtensionAuth(
			baseOptions(server, storage, { encryptRefreshToken: true, clock: () => now }),
		);
		await auth.signIn();
		await storage.local.set({ [REFRESH_KEY]: "attacker-token" });
		now = 4_000_000;
		await expect(auth.getAccessToken()).rejects.toMatchObject({ code: "refresh_failed" });
	});

	it("rejects when the key is gone", async () => {
		const server = fakeServer();
		const storage = fakeStorage();
		let now = 0;
		const make = (keyStore = createMemoryKeyStore()) =>
			createExtensionAuth(
				baseOptions(server, storage, { encryptRefreshToken: true, keyStore, clock: () => now }),
			);
		await make().signIn();
		now = 4_000_000;
		await expect(make(createMemoryKeyStore()).getAccessToken()).rejects.toMatchObject({
			code: "refresh_failed",
		});
	});
});
