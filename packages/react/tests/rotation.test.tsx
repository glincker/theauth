import type { ReactNode } from "react";
import { act, useEffect } from "react";
import type { Root } from "react-dom/client";
import { createRoot } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { KavachProvider } from "../src/context.js";
import { useRotateSession, useUser } from "../src/hooks.js";
import type { ExternalAuthConfig, RotateResult } from "../src/types.js";

// ─── Probe ───────────────────────────────────────────────────────────────────

type Snapshot = {
	rotate: ReturnType<typeof useRotateSession>;
	user: ReturnType<typeof useUser>;
};

let root: Root | null = null;
let latest: Snapshot | null = null;
let fetchMock: ReturnType<typeof vi.fn>;

function Probe() {
	const rotate = useRotateSession();
	const user = useUser();
	useEffect(() => {
		latest = { rotate, user };
	});
	return null;
}

function render(ui: ReactNode) {
	const container = document.createElement("div");
	document.body.appendChild(container);
	root = createRoot(container);
	void act(() => {
		root?.render(ui);
	});
}

async function flush() {
	await act(async () => {
		await Promise.resolve();
		await Promise.resolve();
		await Promise.resolve();
	});
}

function jsonResponse(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json" },
	});
}

const baseConfig = (overrides: Partial<ExternalAuthConfig> = {}): ExternalAuthConfig => ({
	apiUrl: "http://api.example.com",
	mePath: "/api/auth/me",
	loginPath: "/auth/github",
	logoutPath: "/auth/logout",
	refreshPath: "/auth/refresh",
	// Tight retry timings keep the test suite fast.
	retry: {
		maxRetries: 3,
		initialDelayMs: 5,
		backoffMultiplier: 2,
		maxDelayMs: 20,
		requestTimeoutMs: 200,
	},
	// Disable proactive timer by default so individual tests are deterministic.
	proactiveRefreshLeadMs: 0,
	...overrides,
});

beforeEach(() => {
	Object.defineProperty(globalThis, "IS_REACT_ACT_ENVIRONMENT", {
		value: true,
		configurable: true,
		writable: true,
	});
	latest = null;
	document.body.innerHTML = "";
});

afterEach(() => {
	root?.unmount();
	root = null;
	latest = null;
	vi.useRealTimers();
});

// ─── Tests ───────────────────────────────────────────────────────────────────

describe("@glinr/theauth-react v0.5 rotation", () => {
	it("single-flights concurrent rotateSession calls", async () => {
		let refreshCalls = 0;
		fetchMock = vi.fn(async (input: RequestInfo | URL) => {
			const url = typeof input === "string" ? input : input.toString();
			if (url.endsWith("/api/auth/me")) {
				return jsonResponse({ id: "u1", email: "ada@example.com" });
			}
			if (url.endsWith("/auth/refresh")) {
				refreshCalls++;
				// Hold the refresh long enough that the second call sees an
				// in-flight promise.
				await new Promise((r) => setTimeout(r, 10));
				return jsonResponse({
					accessTokenExpiresAt: new Date(Date.now() + 60_000).toISOString(),
				});
			}
			return jsonResponse({}, 404);
		});
		vi.stubGlobal("fetch", fetchMock);

		render(
			<KavachProvider external={baseConfig()}>
				<Probe />
			</KavachProvider>,
		);
		await flush();

		// Fire two rotations back-to-back without awaiting between them.
		let r1: RotateResult | undefined;
		let r2: RotateResult | undefined;
		await act(async () => {
			const p1 = latest!.rotate.rotate();
			const p2 = latest!.rotate.rotate();
			[r1, r2] = await Promise.all([p1, p2]);
		});
		await flush();

		expect(r1?.success).toBe(true);
		expect(r2?.success).toBe(true);
		expect(refreshCalls).toBe(1);
	});

	it("retries on 5xx with exponential backoff and eventually succeeds", async () => {
		let refreshAttempts = 0;
		fetchMock = vi.fn(async (input: RequestInfo | URL) => {
			const url = typeof input === "string" ? input : input.toString();
			if (url.endsWith("/api/auth/me")) {
				return jsonResponse({ id: "u1" });
			}
			if (url.endsWith("/auth/refresh")) {
				refreshAttempts++;
				if (refreshAttempts < 3) {
					return jsonResponse({ error: "boom" }, 500);
				}
				return jsonResponse({
					accessTokenExpiresAt: new Date(Date.now() + 60_000).toISOString(),
				});
			}
			return jsonResponse({}, 404);
		});
		vi.stubGlobal("fetch", fetchMock);

		render(
			<KavachProvider external={baseConfig()}>
				<Probe />
			</KavachProvider>,
		);
		await flush();

		let result: RotateResult | undefined;
		await act(async () => {
			result = await latest!.rotate.rotate();
		});
		await flush();

		expect(result?.success).toBe(true);
		expect(refreshAttempts).toBe(3);
	});

	it("does not retry on 401 and fires onAuthError with the canonical code", async () => {
		const onAuthError = vi.fn();
		let refreshAttempts = 0;
		fetchMock = vi.fn(async (input: RequestInfo | URL) => {
			const url = typeof input === "string" ? input : input.toString();
			if (url.endsWith("/api/auth/me")) {
				return jsonResponse({ id: "u1" });
			}
			if (url.endsWith("/auth/refresh")) {
				refreshAttempts++;
				return jsonResponse({ error: "token_reuse" }, 401);
			}
			return jsonResponse({}, 404);
		});
		vi.stubGlobal("fetch", fetchMock);

		render(
			<KavachProvider external={baseConfig({ onAuthError })}>
				<Probe />
			</KavachProvider>,
		);
		await flush();

		let result: RotateResult | undefined;
		await act(async () => {
			result = await latest!.rotate.rotate();
		});
		await flush();

		expect(result?.success).toBe(false);
		expect(result && !result.success && result.code).toBe("token_reuse");
		expect(refreshAttempts).toBe(1);
		expect(onAuthError).toHaveBeenCalledWith("token_reuse");
		expect(latest?.rotate.status).toBe("error");
	});

	it("schedules a proactive rotation based on accessTokenExpiresAt", async () => {
		vi.useFakeTimers();
		const expiry = new Date(Date.now() + 5_000); // 5s out
		let refreshCalls = 0;
		fetchMock = vi.fn(async (input: RequestInfo | URL) => {
			const url = typeof input === "string" ? input : input.toString();
			if (url.endsWith("/api/auth/me")) {
				return jsonResponse({ id: "u1" });
			}
			if (url.endsWith("/auth/refresh")) {
				refreshCalls++;
				return jsonResponse({ accessTokenExpiresAt: expiry.toISOString() });
			}
			return jsonResponse({}, 404);
		});
		vi.stubGlobal("fetch", fetchMock);

		render(
			<KavachProvider
				external={baseConfig({
					// Lead = 1s — schedule should fire ~4s after the first rotation.
					proactiveRefreshLeadMs: 1_000,
				})}
			>
				<Probe />
			</KavachProvider>,
		);

		// Drain the /me + initial proactive rotation kicked off by the user-load
		// effect.
		await act(async () => {
			await vi.advanceTimersByTimeAsync(50);
		});

		const initialCalls = refreshCalls;
		expect(initialCalls).toBeGreaterThanOrEqual(1);

		// Fast-forward to just past the scheduled proactive trigger. The lead
		// is 1s, expiry is 5s out, so the timer should fire at ~4s.
		await act(async () => {
			await vi.advanceTimersByTimeAsync(5_000);
		});

		expect(refreshCalls).toBeGreaterThan(initialCalls);
	});

	it("is a no-op on the server (rotateSession returns network_error without window)", async () => {
		// Build a minimal context value by exercising the same code path the
		// ManagedProvider uses when rotation isn't configured. We assert the
		// shape of the returned RotateResult — i.e. SSR cannot crash.
		const { useRotateSession: hookUnderTest } = await import("../src/hooks.js");
		const { KavachProvider: P } = await import("../src/context.js");

		// Render in the JSDOM env but with no refreshPath — equivalent to
		// SSR/managed mode behavior at the rotation boundary.
		render(
			<P>
				<Probe />
			</P>,
		);
		await flush();

		let result: RotateResult | undefined;
		await act(async () => {
			result = await latest!.rotate.rotate();
		});

		expect(result?.success).toBe(false);
		expect(result && !result.success && result.code).toBe("network_error");
		expect(typeof hookUnderTest).toBe("function");
	});
});
