import type { ReactNode } from "react";
import { act } from "react";
import type { Root } from "react-dom/client";
import { createRoot } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";
import { TheAuthExpoProvider, useTheAuthContext } from "../src/provider.js";
import { runSocialSignIn } from "../src/social.js";
import { createMemoryStorage, createSecureStoreStorage } from "../src/storage.js";
import type { SocialSignInConfig, TheAuthSession } from "../src/types.js";

const BASE = "https://api.example.com/api/theauth";
const APP = "myapp://auth/callback";
const SESSION: TheAuthSession = { token: "tok", user: { id: "u1", email: "a@b.c" } };

function json(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json" },
	});
}

function social(returnUrl: string | null): {
	config: SocialSignInConfig;
	opened: string[];
} {
	const opened: string[] = [];
	return {
		opened,
		config: {
			redirectUri: APP,
			async openAuthSession(url) {
				opened.push(url);
				return returnUrl ? { type: "success", url: returnUrl } : { type: "cancel" };
			},
		},
	};
}

afterEach(() => {
	vi.unstubAllGlobals();
});

describe("runSocialSignIn", () => {
	it("opens the browser with a PKCE challenge and trades the code with the verifier", async () => {
		const fetchMock = vi.fn(async () => json({ data: SESSION }));
		vi.stubGlobal("fetch", fetchMock);
		const { config, opened } = social(`${APP}?code=abc123`);

		const result = await runSocialSignIn(BASE, "github", config);
		expect(result).toEqual({ success: true, data: SESSION });

		const authorize = opened[0] ?? "";
		expect(authorize).toContain(`${BASE}/auth/oauth/authorize/github?`);
		expect(authorize).toContain(`mobile_redirect=${encodeURIComponent(APP)}`);
		expect(authorize).toContain("code_challenge_method=S256");

		const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
		expect(url).toBe(`${BASE}/auth/oauth/mobile/exchange`);
		const sent = JSON.parse(String(init.body)) as { code: string; code_verifier: string };
		expect(sent.code).toBe("abc123");

		// The challenge in the URL is S256(verifier) from the exchange call.
		const digest = await crypto.subtle.digest(
			"SHA-256",
			new TextEncoder().encode(sent.code_verifier),
		);
		const expected = btoa(String.fromCharCode(...new Uint8Array(digest)))
			.replace(/\+/g, "-")
			.replace(/\//g, "_")
			.replace(/=/g, "");
		expect(authorize).toContain(`code_challenge=${expected}`);
	});

	it("reports cancellation, server errors and gate challenges without calling exchange", async () => {
		const fetchMock = vi.fn();
		vi.stubGlobal("fetch", fetchMock);

		expect(await runSocialSignIn(BASE, "github", social(null).config)).toEqual({
			success: false,
			error: "Sign-in was cancelled",
		});
		expect(
			await runSocialSignIn(BASE, "github", social(`${APP}?error=Account%20exists`).config),
		).toEqual({
			success: false,
			error: "Account exists",
		});
		const gated = await runSocialSignIn(
			BASE,
			"github",
			social(`${APP}#gate=two_factor_required&challenge=x`).config,
		);
		expect(gated.success).toBe(false);
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("surfaces a rejected exchange", async () => {
		vi.stubGlobal(
			"fetch",
			vi.fn(async () => json({ error: "Invalid or expired code" }, 400)),
		);
		const result = await runSocialSignIn(BASE, "github", social(`${APP}?code=x`).config);
		expect(result).toEqual({ success: false, error: "Invalid or expired code" });
	});
});

describe("createSecureStoreStorage", () => {
	it("maps the storage interface onto SecureStore", async () => {
		const calls: string[] = [];
		const storage = createSecureStoreStorage({
			getItemAsync: async (k) => {
				calls.push(`get:${k}`);
				return "v";
			},
			setItemAsync: async (k, v) => void calls.push(`set:${k}=${v}`),
			deleteItemAsync: async (k) => void calls.push(`del:${k}`),
		});
		expect(await storage.getItem("a")).toBe("v");
		await storage.setItem("a", "b");
		await storage.removeItem("a");
		expect(calls).toEqual(["get:a", "set:a=b", "del:a"]);
	});
});

describe("provider", () => {
	let root: Root | null = null;
	afterEach(() => {
		act(() => root?.unmount());
		root = null;
	});

	async function mount(config: Parameters<typeof TheAuthExpoProvider>[0]["config"]) {
		let ctx: ReturnType<typeof useTheAuthContext> | null = null;
		function Probe(): ReactNode {
			ctx = useTheAuthContext();
			return null;
		}
		const el = document.createElement("div");
		root = createRoot(el);
		await act(async () => {
			root?.render(
				<TheAuthExpoProvider config={config}>
					<Probe />
				</TheAuthExpoProvider>,
			);
			await Promise.resolve();
		});
		return () => ctx as unknown as ReturnType<typeof useTheAuthContext>;
	}

	it("stores the session after signInWithProvider and refreshes on foreground", async () => {
		const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
			const url = String(input);
			if (url.endsWith("/mobile/exchange")) return json({ data: SESSION });
			if (url.endsWith("/session")) return json({ data: SESSION });
			return json({}, 404);
		});
		vi.stubGlobal("fetch", fetchMock);
		const storage = createMemoryStorage();
		let onChange: ((s: string) => void) | null = null;
		const removed = vi.fn();
		const get = await mount({
			basePath: BASE,
			storage,
			social: social(`${APP}?code=abc`).config,
			appState: {
				addEventListener(_t, listener) {
					onChange = listener;
					return { remove: removed };
				},
			},
		});

		let result: Awaited<ReturnType<ReturnType<typeof get>["signInWithProvider"]>> | null = null;
		await act(async () => {
			result = await get().signInWithProvider("github");
		});
		expect(result).toEqual({ success: true, data: undefined });
		expect(await storage.getItem("theauth_session")).toBe("tok");
		expect(get().isAuthenticated).toBe(true);

		const before = fetchMock.mock.calls.filter(([u]) => String(u).endsWith("/session")).length;
		await act(async () => {
			(onChange as ((s: string) => void) | null)?.("active");
			await Promise.resolve();
			await Promise.resolve();
		});
		const after = fetchMock.mock.calls.filter(([u]) => String(u).endsWith("/session")).length;
		expect(after).toBe(before + 1);
	});

	it("says so when social sign-in is not configured", async () => {
		vi.stubGlobal(
			"fetch",
			vi.fn(async () => json({}, 401)),
		);
		const get = await mount({ basePath: BASE, storage: createMemoryStorage() });
		let result: unknown = null;
		await act(async () => {
			result = await get().signInWithProvider("github");
		});
		expect(result).toEqual({ success: false, error: "Social sign-in is not configured" });
	});
});
