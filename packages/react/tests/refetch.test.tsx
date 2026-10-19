import type { ReactNode } from "react";
import { act } from "react";
import type { Root } from "react-dom/client";
import { createRoot } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { TheAuthProvider, useTheAuthContext } from "../src/context.js";

let root: Root | null = null;
let ctx: ReturnType<typeof useTheAuthContext> | null = null;

function Probe() {
	ctx = useTheAuthContext();
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

async function settle() {
	await act(async () => {
		await Promise.resolve();
		await Promise.resolve();
		await Promise.resolve();
	});
}

const json = (status: number, body: unknown) =>
	new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

beforeEach(() => {
	Object.defineProperty(globalThis, "IS_REACT_ACT_ENVIRONMENT", {
		value: true,
		configurable: true,
		writable: true,
	});
	window.localStorage.clear();
	ctx = null;
});

afterEach(() => {
	act(() => root?.unmount());
	root = null;
	vi.useRealTimers();
	vi.unstubAllGlobals();
});

describe("managed provider session refetch", () => {
	it("hydrates from managed.initialSession with no request, then refetches on focus", async () => {
		const fetchMock = vi.fn(async () => json(200, { user: { id: "u2", name: "Fresh" } }));
		vi.stubGlobal("fetch", fetchMock);
		render(
			<TheAuthProvider
				managed={{ initialSession: { user: { id: "u1" } }, refetch: { onFocus: true } }}
			>
				<Probe />
			</TheAuthProvider>,
		);
		await settle();
		expect(ctx?.user?.id).toBe("u1");
		expect(ctx?.isLoading).toBe(false);
		expect(fetchMock).not.toHaveBeenCalled();
		await act(async () => {
			window.dispatchEvent(new Event("focus"));
			await Promise.resolve();
		});
		await settle();
		expect(fetchMock).toHaveBeenCalledTimes(1);
		expect(fetchMock.mock.calls[0]?.[0]).toBe("/api/theauth/auth/session");
		expect(ctx?.user?.id).toBe("u2");
	});

	it("stops refetching after unmount", async () => {
		const fetchMock = vi.fn(async () => json(200, { user: { id: "u1" } }));
		vi.stubGlobal("fetch", fetchMock);
		render(
			<TheAuthProvider
				managed={{ initialSession: { user: { id: "u1" } }, refetch: { onFocus: true } }}
			>
				<Probe />
			</TheAuthProvider>,
		);
		await settle();
		act(() => root?.unmount());
		root = null;
		window.dispatchEvent(new Event("focus"));
		await Promise.resolve();
		expect(fetchMock).not.toHaveBeenCalled();
	});
});

describe("external provider session refetch", () => {
	it("refetches on an interval and keeps the user through a network error", async () => {
		vi.useFakeTimers();
		let mode: "ok" | "down" = "ok";
		const fetchMock = vi.fn(async () => {
			if (mode === "down") throw new TypeError("offline");
			return json(200, { id: "ext-1" });
		});
		vi.stubGlobal("fetch", fetchMock);
		render(
			<TheAuthProvider
				external={{
					apiUrl: "https://api.example.test",
					refreshPath: "",
					refetch: { intervalMs: 1000, onFocus: false, onReconnect: false },
				}}
			>
				<Probe />
			</TheAuthProvider>,
		);
		await act(async () => {
			await vi.advanceTimersByTimeAsync(0);
		});
		expect(ctx?.user?.id).toBe("ext-1");
		const before = fetchMock.mock.calls.length;
		await act(async () => {
			await vi.advanceTimersByTimeAsync(1000);
		});
		expect(fetchMock.mock.calls.length).toBe(before + 1);
		mode = "down";
		await act(async () => {
			await vi.advanceTimersByTimeAsync(1000);
		});
		expect(ctx?.user?.id).toBe("ext-1");
	});

	it("initialUser skips the first request", async () => {
		const fetchMock = vi.fn();
		vi.stubGlobal("fetch", fetchMock);
		render(
			<TheAuthProvider
				external={{
					apiUrl: "https://api.example.test",
					refreshPath: "",
					initialUser: { id: "seed" },
				}}
			>
				<Probe />
			</TheAuthProvider>,
		);
		await settle();
		expect(ctx?.user?.id).toBe("seed");
		expect(ctx?.isLoading).toBe(false);
		expect(fetchMock).not.toHaveBeenCalled();
	});
});
