import type { ReactNode } from "react";
import { act, useEffect } from "react";
import type { Root } from "react-dom/client";
import { createRoot } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { KavachProvider, useKavachContext } from "../src/context.js";
import { useAgents, useSession, useSignIn, useSignOut, useSignUp, useUser } from "../src/hooks.js";
import type { ActionResult, KavachAgent, KavachSession } from "../src/types.js";

type Snapshot = {
	context: ReturnType<typeof useKavachContext>;
	session: ReturnType<typeof useSession>;
	user: ReturnType<typeof useUser>;
	signIn: ReturnType<typeof useSignIn>;
	signUp: ReturnType<typeof useSignUp>;
	signOut: ReturnType<typeof useSignOut>;
	agents: ReturnType<typeof useAgents>;
};

const SESSION_KEY = "kavach_session";

let root: Root | null = null;
let latest: Snapshot | null = null;
let fetchMock: ReturnType<typeof vi.fn>;

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

beforeEach(() => {
	Object.defineProperty(globalThis, "IS_REACT_ACT_ENVIRONMENT", {
		value: true,
		configurable: true,
		writable: true,
	});

	fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
		const url = typeof input === "string" ? input : input.toString();
		const parsed = new URL(url, "http://localhost");

		if (parsed.pathname === "/api/kavach/auth/sign-up" && init?.method === "POST") {
			return jsonResponse({
				user: {
					id: "user-2",
					email: "new@example.com",
					name: "New User",
				},
				token: "signup-token",
			});
		}

		if (parsed.pathname === "/api/kavach/auth/sign-in" && init?.method === "POST") {
			return jsonResponse({
				user: {
					id: "user-1",
					email: "ada@example.com",
					name: "Ada",
				},
				session: {
					token: "signin-token",
					expiresAt: "2026-04-01T00:00:00.000Z",
				},
			});
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
	window.localStorage.clear();
});

afterEach(() => {
	root?.unmount();
	root = null;
	latest = null;
	agentsState = [];
});

let agentsState: KavachAgent[] = [];

describe("@theauth/react runtime smoke", () => {
	it("restores the provider session from localStorage and loads agents", async () => {
		const storedSession: KavachSession = {
			token: "stored-token",
			user: {
				id: "user-1",
				email: "ada@example.com",
				name: "Ada",
			},
			expiresAt: "2026-04-01T00:00:00.000Z",
		};
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

		window.localStorage.setItem(SESSION_KEY, JSON.stringify(storedSession));

		render(
			<KavachProvider>
				<Probe />
			</KavachProvider>,
		);
		await flush();

		expect(latest?.context.isAuthenticated).toBe(true);
		expect(latest?.session.session?.token).toBe("stored-token");
		expect(latest?.user.user?.id).toBe("user-1");
		expect(latest?.agents.agents).toHaveLength(1);
		expect(fetchMock).toHaveBeenCalledWith(
			expect.stringContaining("/api/kavach/agents?userId=user-1"),
			expect.objectContaining({ credentials: "include" }),
		);
	});

	it("signs up and signs out through the provider", async () => {
		agentsState = [];

		render(
			<KavachProvider>
				<Probe />
			</KavachProvider>,
		);
		await flush();

		let signUpResult: ActionResult | undefined;
		await act(async () => {
			signUpResult = await latest!.signUp.signUp("new@example.com", "secret123", "New User");
		});
		await flush();

		expect(signUpResult).toEqual({ success: true, data: undefined });
		expect(latest?.context.isAuthenticated).toBe(true);
		expect(latest?.user.user?.id).toBe("user-2");
		expect(JSON.parse(window.localStorage.getItem(SESSION_KEY) ?? "{}")).toMatchObject({
			token: "signup-token",
			user: { id: "user-2" },
		});

		await act(async () => {
			await latest!.signOut.signOut();
		});
		await flush();

		expect(latest?.context.session).toBeNull();
		expect(latest?.context.isAuthenticated).toBe(false);
		expect(window.localStorage.getItem(SESSION_KEY)).toBeNull();
	});

	it("creates, rotates, and revokes agents through the public hook", async () => {
		const storedSession: KavachSession = {
			token: "stored-token",
			user: {
				id: "user-1",
				email: "ada@example.com",
				name: "Ada",
			},
		};
		agentsState = [
			{
				id: "agent-1",
				ownerId: "user-1",
				name: "Reader",
				type: "service",
				token: "agent-token",
				permissions: [],
				status: "active",
				expiresAt: null,
				createdAt: "2026-03-01T00:00:00.000Z",
				updatedAt: "2026-03-02T00:00:00.000Z",
			},
		];

		window.localStorage.setItem(SESSION_KEY, JSON.stringify(storedSession));

		render(
			<KavachProvider>
				<Probe />
			</KavachProvider>,
		);
		await flush();

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
		expect(latest?.agents.agents).toHaveLength(2);

		let rotated: ActionResult<KavachAgent> | undefined;
		await act(async () => {
			rotated = await latest!.agents.rotate("agent-reporter");
		});
		await flush();

		expect(rotated?.success).toBe(true);
		expect(latest?.agents.agents.find((agent) => agent.id === "agent-reporter")?.token).toBe(
			"created-token-rotated",
		);

		let revoked: ActionResult | undefined;
		await act(async () => {
			revoked = await latest!.agents.revoke("agent-reporter");
		});
		await flush();

		expect(revoked?.success).toBe(true);
		expect(latest?.agents.agents).toHaveLength(1);
	});
});
