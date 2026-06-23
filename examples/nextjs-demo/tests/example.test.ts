import { beforeEach, describe, expect, it, vi } from "vitest";
import { emailPassword } from "../../../packages/auth/email/src/index.js";
import type { Kavach } from "../../../packages/core/src/kavach.js";
import { createAuth } from "../../../packages/core/src/kavach.js";

const state = vi.hoisted(() => ({ kavach: null as Kavach | null }));

vi.mock("@/lib/kavach", () => ({
	getKavach: async () => state.kavach,
}));

vi.mock("@glinr/theauth-nextjs", async () => {
	return import("../../../packages/adapters/nextjs/src/adapter.ts");
});

async function loadRouteModule() {
	vi.resetModules();
	return import("../app/api/kavach/[...kavach]/route.ts");
}

function getField<T>(body: Record<string, unknown>, key: string): T | undefined {
	const direct = body[key];
	if (direct !== undefined) {
		return direct as T;
	}

	const nested = body.data;
	if (nested && typeof nested === "object" && key in nested) {
		return (nested as Record<string, unknown>)[key] as T;
	}

	return undefined;
}

describe("nextjs-demo example", () => {
	beforeEach(async () => {
		state.kavach = await createAuth({
			database: { provider: "sqlite", url: ":memory:" },
			agents: {
				enabled: true,
				maxPerUser: 10,
				defaultPermissions: [],
				auditAll: true,
				tokenExpiry: "24h",
			},
			plugins: [
				emailPassword({
					appUrl: "http://localhost:3002",
					requireVerification: false,
					sendVerificationEmail: async () => {},
					sendResetEmail: async () => {},
				}),
			],
		});
	});

	it("serves the auth flow and agent routes under /api/kavach", async () => {
		const route = await loadRouteModule();

		const signUpRes = await route.POST(
			new Request("http://localhost/api/kavach/auth/sign-up", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({
					email: "demo@example.com",
					password: "Password123!",
					name: "Demo User",
				}),
			}),
		);
		expect(signUpRes.status).toBe(201);
		const signUpBody = (await signUpRes.json()) as Record<string, unknown>;
		const signedUpUser = getField<{ id: string; email: string }>(signUpBody, "user");
		expect(signedUpUser?.email).toBe("demo@example.com");

		const signInRes = await route.POST(
			new Request("http://localhost/api/kavach/auth/sign-in", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({
					email: "demo@example.com",
					password: "Password123!",
				}),
			}),
		);
		expect(signInRes.status).toBe(200);
		const signInBody = (await signInRes.json()) as Record<string, unknown>;
		const session = getField<{ token: string }>(signInBody, "session");
		const signedInUser = getField<{ id: string; email: string }>(signInBody, "user");
		expect(typeof session?.token).toBe("string");
		expect(session?.token.length).toBeGreaterThan(10);
		expect(signedInUser?.email).toBe("demo@example.com");

		const createAgentRes = await route.POST(
			new Request("http://localhost/api/kavach/agents", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({
					ownerId: signedInUser?.id,
					name: "demo-agent",
					type: "autonomous",
					permissions: [{ resource: "documents", actions: ["read"] }],
				}),
			}),
		);
		expect(createAgentRes.status).toBe(201);
		const createdAgent = (await createAgentRes.json()) as {
			data: { id: string; token: string };
		};

		const authorizeRes = await route.POST(
			new Request("http://localhost/api/kavach/authorize/token", {
				method: "POST",
				headers: {
					Authorization: `Bearer ${createdAgent.data.token}`,
					"Content-Type": "application/json",
				},
				body: JSON.stringify({
					action: "read",
					resource: "documents",
				}),
			}),
		);
		expect(authorizeRes.status).toBe(200);
		expect(((await authorizeRes.json()) as { data: { allowed: boolean } }).data.allowed).toBe(true);
	});
});
