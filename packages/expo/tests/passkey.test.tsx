import type { ReactNode } from "react";
import { act } from "react";
import type { Root } from "react-dom/client";
import { createRoot } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";
import { runPasskeyRegistration, runPasskeySignIn } from "../src/passkey.js";
import { TheAuthExpoProvider, useTheAuthContext } from "../src/provider.js";
import { createMemoryStorage } from "../src/storage.js";
import type { PasskeyAuthenticator } from "../src/types.js";

const BASE = "https://api.example.com/api/theauth";

function json(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json" },
	});
}

function authenticator(over: Partial<PasskeyAuthenticator> = {}): PasskeyAuthenticator {
	return {
		create: vi.fn(async () => ({ id: "cred", rawId: "cred", type: "public-key", response: {} })),
		get: vi.fn(async () => ({ id: "cred", rawId: "cred", type: "public-key", response: {} })),
		...over,
	};
}

function router(routes: Record<string, () => Response>) {
	return vi.fn(async (input: RequestInfo | URL) => {
		const path = String(input).replace(BASE, "");
		const handler = routes[path];
		return handler ? handler() : json({ error: "not found" }, 404);
	});
}

const SIGN_IN_ROUTES = {
	"/auth/passkey/authenticate/options": () => json({ challenge: "c", rpId: "example.com" }),
	"/auth/passkey/authenticate/verify": () =>
		json({ user: { id: "u1" }, session: { token: "tok", expiresAt: "2026-12-01T00:00:00Z" } }),
};

describe("runPasskeySignIn", () => {
	it("passes the server options to the authenticator and returns the session", async () => {
		const fetchFn = router(SIGN_IN_ROUTES);
		const auth = authenticator();
		const result = await runPasskeySignIn(BASE, auth, fetchFn as unknown as typeof fetch);

		expect(result).toEqual({
			success: true,
			data: { token: "tok", user: { id: "u1" }, expiresAt: "2026-12-01T00:00:00Z" },
		});
		expect(auth.get).toHaveBeenCalledWith({ challenge: "c", rpId: "example.com" });
		const verifyCall = fetchFn.mock.calls[1] as unknown as [string, RequestInit];
		expect(JSON.parse(String(verifyCall[1].body))).toHaveProperty("response.id", "cred");
	});

	it("reports a cancelled prompt without calling verify", async () => {
		const fetchFn = router(SIGN_IN_ROUTES);
		const auth = authenticator({
			get: vi.fn(async () => {
				throw new Error("User cancelled");
			}),
		});
		const result = await runPasskeySignIn(BASE, auth, fetchFn as unknown as typeof fetch);
		expect(result).toEqual({ success: false, error: "User cancelled" });
		expect(fetchFn).toHaveBeenCalledTimes(1);
	});

	it("surfaces a rejected assertion and a sign-in gate", async () => {
		const rejected = router({
			...SIGN_IN_ROUTES,
			"/auth/passkey/authenticate/verify": () => json({ error: "Authentication failed" }, 401),
		});
		expect(
			await runPasskeySignIn(BASE, authenticator(), rejected as unknown as typeof fetch),
		).toEqual({
			success: false,
			error: "Authentication failed",
		});

		const gated = router({
			...SIGN_IN_ROUTES,
			"/auth/passkey/authenticate/verify": () =>
				json({ error: "Second factor required", gate: "two_factor_required", challenge: "x" }, 403),
		});
		const out = await runPasskeySignIn(BASE, authenticator(), gated as unknown as typeof fetch);
		expect(out.success).toBe(false);
		if (!out.success) expect(out.error).toContain("two_factor_required");
	});
});

describe("runPasskeyRegistration", () => {
	it("creates the credential with the session token and stores it", async () => {
		const fetchFn = router({
			"/auth/passkey/register/options": () => json({ challenge: "r", rp: { id: "example.com" } }),
			"/auth/passkey/register/verify": () => json({ credential: { id: "cred" } }),
		});
		const auth = authenticator();
		const result = await runPasskeyRegistration(
			BASE,
			auth,
			fetchFn as unknown as typeof fetch,
			"sess",
			"Pixel 9",
		);
		expect(result).toEqual({ success: true, data: undefined });
		const [, init] = fetchFn.mock.calls[0] as unknown as [string, RequestInit];
		expect((init.headers as Record<string, string>).Authorization).toBe("Bearer sess");
		const verify = fetchFn.mock.calls[1] as unknown as [string, RequestInit];
		expect(JSON.parse(String(verify[1].body))).toHaveProperty("response.deviceName", "Pixel 9");
	});
});

describe("provider passkeys", () => {
	let root: Root | null = null;
	afterEach(() => {
		act(() => root?.unmount());
		root = null;
	});

	it("uses the injected fetch, stores the session and requires a session to register", async () => {
		const fetchFn = router({
			...SIGN_IN_ROUTES,
			"/auth/session": () => json({ data: { token: "tok", user: { id: "u1", email: "a@b.c" } } }),
			"/auth/passkey/register/options": () => json({ challenge: "r" }),
			"/auth/passkey/register/verify": () => json({}),
		});
		const storage = createMemoryStorage();
		let ctx: ReturnType<typeof useTheAuthContext> | null = null;
		function Probe(): ReactNode {
			ctx = useTheAuthContext();
			return null;
		}
		const el = document.createElement("div");
		root = createRoot(el);
		await act(async () => {
			root?.render(
				<TheAuthExpoProvider
					config={{
						basePath: BASE,
						storage,
						passkeys: authenticator(),
						fetch: fetchFn as unknown as typeof fetch,
					}}
				>
					<Probe />
				</TheAuthExpoProvider>,
			);
			await Promise.resolve();
		});
		const get = () => ctx as unknown as ReturnType<typeof useTheAuthContext>;

		let early: unknown = null;
		await act(async () => {
			early = await get().registerPasskey();
		});
		expect(early).toEqual({ success: false, error: "Sign in before adding a passkey" });

		let result: unknown = null;
		await act(async () => {
			result = await get().signInWithPasskey();
			await Promise.resolve();
		});
		expect(result).toEqual({ success: true, data: undefined });
		expect(await storage.getItem("theauth_session")).toBe("tok");
		expect(get().isAuthenticated).toBe(true);
	});
});
