import type { ReactNode } from "react";
import { act, useEffect } from "react";
import type { Root } from "react-dom/client";
import { createRoot } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useAgents, useSession, useSignIn, useSignOut, useSignUp, useUser } from "../src/hooks.js";
import { KavachExpoProvider, useKavachContext } from "../src/provider.js";
import { createMemoryStorage } from "../src/storage.js";
import type { ActionResult, KavachAgent } from "../src/types.js";

type Snapshot = {
	context: ReturnType<typeof useKavachContext>;
	session: ReturnType<typeof useSession>;
	user: ReturnType<typeof useUser>;
	signIn: ReturnType<typeof useSignIn>;
	signUp: ReturnType<typeof useSignUp>;
	signOut: ReturnType<typeof useSignOut>;
	agents: ReturnType<typeof useAgents>;
};

const SESSION_KEY = "theauth_session";

let root: Root | null = null;
let latest: Snapshot | null = null;
let fetchMock: ReturnType<typeof vi.fn>;
let storage = createMemoryStorage();
let agentsState: KavachAgent[] = [];

function jsonResponse(body: unknown, status = 200): Response {
	return new Response(body === null ? null : JSON.stringify(body), {
		status,
		headers: body === null ? undefined : { "Content-Type": "application/json" },
	});
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
	});
}

async function waitForCondition(predicate: () => boolean) {
	for (let i = 0; i < 20; i += 1) {
		if (predicate()) return;
		await flush();
	}
	throw new Error("timed out waiting for state");
}

function Probe() {
	const context = useKavachContext();
	const session = useSession();
	const user = useUser();
	const signIn = useSignIn();
	const signUp = useSignUp();
	const signOut = useSignOut();
	const agents = useAgents("/api/kavach");

	useEffect(() => {
		latest = { context, session, user, signIn, signUp, signOut, agents };
	});

	return null;
}

beforeEach(async () => {
	Object.defineProperty(globalThis, "IS_REACT_ACT_ENVIRONMENT", {
		value: true,
		configurable: true,
		writable: true,
	});

	storage = createMemoryStorage();
	agentsState = [];

	fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
		const url = typeof input === "string" ? input : input.toString();
		const parsed = new URL(url, "http://localhost");
		const authHeader = new Headers(init?.headers).get("Authorization");

		if (parsed.pathname === "/api/kavach/session" && authHeader === "Bearer stored-token") {
			return jsonResponse({
				data: {
					token: "stored-token",
					user: {
						id: "user-1",
						email: "ada@example.com",
						name: "Ada",
					},
					expiresAt: "2026-04-01T00:00:00.000Z",
				},
			});
		}

		if (parsed.pathname === "/api/kavach/sign-in/email" && init?.method === "POST") {
			return jsonResponse({
				data: {
					token: "signin-token",
					user: {
						id: "user-1",
						email: "ada@example.com",
						name: "Ada",
					},
					expiresAt: "2026-04-01T00:00:00.000Z",
				},
			});
		}

		if (parsed.pathname === "/api/kavach/sign-up/email" && init?.method === "POST") {
			return jsonResponse({
				data: {
					token: "signup-token",
					user: {
						id: "user-2",
						email: "new@example.com",
						name: "New User",
					},
				},
			});
		}

		if (parsed.pathname === "/api/kavach/sign-out" && init?.method === "POST") {
			return new Response(null, { status: 204 });
		}

		if (parsed.pathname === "/api/kavach/agents" && init?.method === "POST") {
			const payload = JSON.parse(String(init.body ?? "{}")) as {
				ownerId: string;
				name: string;
				type: KavachAgent["type"];
				permissions: KavachAgent["permissions"];
			};
			const agent: KavachAgent = {
				id: `agent-${payload.name.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`,
				ownerId: payload.ownerId,
				name: payload.name,
				type: payload.type,
				token: "created-token",
				permissions: payload.permissions,
				status: "active",
				expiresAt: null,
				createdAt: "2026-03-29T12:00:00.000Z",
				updatedAt: "2026-03-29T12:00:00.000Z",
			};
			agentsState = [...agentsState, agent];
			return jsonResponse({ data: agent });
		}

		if (parsed.pathname.startsWith("/api/kavach/agents/") && parsed.pathname.endsWith("/rotate")) {
			const agentId = parsed.pathname.split("/")[4];
			agentsState = agentsState.map((agent) =>
				agent.id === agentId
					? { ...agent, token: `${agent.token}-rotated`, updatedAt: "2026-03-29T12:05:00.000Z" }
					: agent,
			);
			const agent = agentsState.find((item) => item.id === agentId);
			if (!agent) return jsonResponse({ error: { code: "NOT_FOUND", message: "missing" } }, 404);
			return jsonResponse({ data: agent });
		}

		if (parsed.pathname.startsWith("/api/kavach/agents/") && init?.method === "DELETE") {
			const agentId = parsed.pathname.split("/")[4];
			agentsState = agentsState.filter((agent) => agent.id !== agentId);
			return new Response(null, { status: 204 });
		}

		if (parsed.pathname === "/api/kavach/agents" && init?.method !== "POST") {
			return jsonResponse({ data: agentsState });
		}

		return jsonResponse({ error: { code: "UNMOCKED", message: parsed.pathname } }, 404);
	});

	vi.stubGlobal("fetch", fetchMock);
	latest = null;
	document.body.innerHTML = "";
});

afterEach(() => {
	root?.unmount();
	root = null;
	latest = null;
});

describe("@glinr/theauth-expo runtime smoke", () => {
	it("restores a stored session, authenticates agent requests, and loads agents", async () => {
		await storage.setItem(SESSION_KEY, "stored-token");
		agentsState = [
			{
				id: "agent-1",
				ownerId: "user-1",
				name: "Reader",
				type: "service",
				token: "agent-token",
				permissions: [
					{
						resource: "reports:*",
						actions: ["read"],
					},
				],
				status: "active",
				expiresAt: null,
				createdAt: "2026-03-01T00:00:00.000Z",
				updatedAt: "2026-03-02T00:00:00.000Z",
			},
		];

		render(
			<KavachExpoProvider config={{ basePath: "/api/kavach", storage }}>
				<Probe />
			</KavachExpoProvider>,
		);
		await waitForCondition(() => latest?.context.isAuthenticated === true);
		expect(latest?.session.session?.token).toBe("stored-token");
		expect(latest?.user.user?.id).toBe("user-1");
		expect(latest?.agents.agents).toHaveLength(1);
		expect(
			fetchMock.mock.calls.some(
				([input, init]) =>
					String(input).includes("/api/kavach/session") &&
					new Headers(init?.headers).get("Authorization") === "Bearer stored-token",
			),
		).toBe(true);
		expect(
			fetchMock.mock.calls.some(
				([input, init]) =>
					String(input).includes("/api/kavach/agents?userId=user-1") &&
					new Headers(init?.headers).get("Authorization") === "Bearer stored-token",
			),
		).toBe(true);
	});

	it("signs in, mutates agents, and clears storage on sign out", async () => {
		render(
			<KavachExpoProvider config={{ basePath: "/api/kavach", storage }}>
				<Probe />
			</KavachExpoProvider>,
		);
		await flush();

		let signInResult: ActionResult | undefined;
		await act(async () => {
			signInResult = await latest!.signIn.signIn("ada@example.com", "secret123");
		});
		await flush();

		expect(signInResult).toEqual({ success: true, data: undefined });
		expect(await storage.getItem(SESSION_KEY)).toBe("signin-token");
		expect(latest?.context.isAuthenticated).toBe(true);

		let created: ActionResult<KavachAgent> | undefined;
		await act(async () => {
			created = await latest!.agents.create({
				ownerId: "user-1",
				name: "Reporter",
				type: "service",
				permissions: [
					{
						resource: "reports:*",
						actions: ["read"],
					},
				],
			});
		});
		await flush();

		expect(created?.success).toBe(true);
		expect(latest?.agents.agents).toHaveLength(1);

		let rotated: ActionResult<KavachAgent> | undefined;
		await act(async () => {
			rotated = await latest!.agents.rotate("agent-reporter");
		});
		await flush();

		expect(rotated?.success).toBe(true);
		expect(latest?.agents.agents[0]?.token).toBe("created-token-rotated");

		let revoked: ActionResult | undefined;
		await act(async () => {
			revoked = await latest!.agents.revoke("agent-reporter");
		});
		await flush();

		expect(revoked?.success).toBe(true);
		expect(latest?.agents.agents).toHaveLength(0);

		await act(async () => {
			await latest!.signOut.signOut();
		});
		await flush();

		expect(await storage.getItem(SESSION_KEY)).toBeNull();
		expect(latest?.context.session).toBeNull();
	});
});
