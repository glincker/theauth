import { describe, expect, it } from "vitest";
import type { MessageSenderLike, RuntimeLike } from "../src/index.js";
import { createAuthClient, createExtensionAuth, exposeAuthToBackground } from "../src/index.js";
import { baseOptions, fakeServer, fakeStorage } from "./helpers.js";

const OWN_ID = "own-extension-id";
const BASE = `chrome-extension://${OWN_ID}/`;

type Listener = Parameters<RuntimeLike["onMessage"]["addListener"]>[0];

function fakeRuntime() {
	const internal = new Set<Listener>();
	const external = new Set<Listener>();
	const runtime: RuntimeLike = {
		id: OWN_ID,
		getURL: (p) => `${BASE}${p}`,
		sendMessage: async () => undefined,
		onMessage: {
			addListener: (l) => internal.add(l),
			removeListener: (l) => internal.delete(l),
		},
		onMessageExternal: {
			addListener: (l) => external.add(l),
			removeListener: (l) => external.delete(l),
		},
	};
	/** Deliver a message to the registered listeners and await the response. */
	async function deliver(
		set: Set<Listener>,
		message: unknown,
		sender: MessageSenderLike,
	): Promise<unknown> {
		for (const l of set) {
			const out = await new Promise<unknown>((resolve) => {
				const keep = l(message, sender, resolve);
				if (keep !== true) setTimeout(() => resolve("no-response"), 0);
			});
			return out;
		}
		return "no-listener";
	}
	return { runtime, internal, external, deliver };
}

async function signedInAuth() {
	const auth = createExtensionAuth(baseOptions(fakeServer(), fakeStorage()));
	await auth.signIn();
	return auth;
}

const REQ = (method: string) => ({ channel: "theauth:extension", v: 1, method });

describe("message passing", () => {
	it("serves the access token to the extension's own content script and never the refresh token", async () => {
		const auth = await signedInAuth();
		const rt = fakeRuntime();
		exposeAuthToBackground(auth, { runtime: rt.runtime });
		const content: MessageSenderLike = { id: OWN_ID, url: "https://site.example/page", tab: {} };
		const res = await rt.deliver(rt.internal, REQ("getAccessToken"), content);
		expect(res).toMatchObject({ ok: true, data: "at-1" });
		const session = await rt.deliver(rt.internal, REQ("getSession"), content);
		expect(JSON.stringify(session)).not.toContain("rt-1");
	});

	it("rejects an external sender when no allowlist is configured", async () => {
		const auth = await signedInAuth();
		const rt = fakeRuntime();
		exposeAuthToBackground(auth, { runtime: rt.runtime });
		expect(rt.external.size).toBe(0);
		const res = await rt.deliver(rt.internal, REQ("getAccessToken"), { id: "other-extension" });
		expect(res).toMatchObject({ ok: false, error: { code: "message_rejected" } });
		const noId = await rt.deliver(rt.internal, REQ("getAccessToken"), {});
		expect(noId).toMatchObject({ ok: false });
	});

	it("accepts external senders only from the allowlist", async () => {
		const auth = await signedInAuth();
		const rt = fakeRuntime();
		exposeAuthToBackground(auth, { runtime: rt.runtime, allowedExtensionIds: ["friend"] });
		const ok = await rt.deliver(rt.external, REQ("getAccessToken"), { id: "friend" });
		expect(ok).toMatchObject({ ok: true, data: "at-1" });
		const no = await rt.deliver(rt.external, REQ("getAccessToken"), { id: "stranger" });
		expect(no).toMatchObject({ ok: false, error: { code: "message_rejected" } });
	});

	it("keeps sign out away from content scripts but allows it from extension pages", async () => {
		const auth = await signedInAuth();
		const rt = fakeRuntime();
		exposeAuthToBackground(auth, { runtime: rt.runtime });
		const script: MessageSenderLike = { id: OWN_ID, url: "https://site.example/", tab: {} };
		const denied = await rt.deliver(rt.internal, REQ("signOut"), script);
		expect(denied).toMatchObject({ ok: false, error: { code: "message_rejected" } });
		expect(await auth.getSession()).not.toBeNull();

		const popup: MessageSenderLike = { id: OWN_ID, url: `${BASE}popup.html` };
		const done = await rt.deliver(rt.internal, REQ("signOut"), popup);
		expect(done).toMatchObject({ ok: true });
		expect(await auth.getSession()).toBeNull();
	});

	it("ignores unrelated messages and unknown methods", async () => {
		const auth = await signedInAuth();
		const rt = fakeRuntime();
		exposeAuthToBackground(auth, { runtime: rt.runtime });
		const popup: MessageSenderLike = { id: OWN_ID, url: `${BASE}popup.html` };
		expect(await rt.deliver(rt.internal, { hello: 1 }, popup)).toBe("no-response");
		expect(await rt.deliver(rt.internal, REQ("exportRefreshToken"), popup)).toBe("no-response");
	});

	it("round trips through createAuthClient and surfaces typed errors", async () => {
		const auth = createExtensionAuth(baseOptions(fakeServer(), fakeStorage()));
		const rt = fakeRuntime();
		exposeAuthToBackground(auth, { runtime: rt.runtime });
		const popup: MessageSenderLike = { id: OWN_ID, url: `${BASE}popup.html` };
		const client = createAuthClient({
			runtime: {
				...rt.runtime,
				sendMessage: (message: unknown) => rt.deliver(rt.internal, message, popup),
			},
		});
		await expect(client.getAccessToken()).rejects.toMatchObject({ code: "not_signed_in" });
		await client.signIn();
		expect(await client.getAccessToken()).toBe("at-1");
	});

	it("removes its listeners", async () => {
		const auth = await signedInAuth();
		const rt = fakeRuntime();
		const stop = exposeAuthToBackground(auth, {
			runtime: rt.runtime,
			allowedExtensionIds: ["friend"],
		});
		expect(rt.internal.size).toBe(1);
		stop();
		expect(rt.internal.size).toBe(0);
		expect(rt.external.size).toBe(0);
	});
});
