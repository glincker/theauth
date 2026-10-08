import { describe, expect, it, vi } from "vitest";
import type { DeviceAuthConfig } from "../src/auth/device-auth.js";
import { createDeviceAuthModule, deviceAuth } from "../src/auth/device-auth.js";
import { sha256 } from "../src/crypto/web-crypto.js";
import * as schema from "../src/db/schema.js";
import { memoryStorage } from "../src/storage/index.js";
import { createTheAuth } from "../src/theauth.js";

const BASE: DeviceAuthConfig = { verificationUri: "https://app.example.com/device" };
const SECRET = "x".repeat(40);

const jsonReq = (path: string, body: unknown, headers: Record<string, string> = {}) =>
	new Request(`https://app.example.com${path}`, {
		method: "POST",
		headers: { "content-type": "application/json", ...headers },
		body: JSON.stringify(body),
	});

describe("storage hygiene", () => {
	it("never stores the raw device code or user code", async () => {
		const storage = memoryStorage();
		const mod = createDeviceAuthModule({ ...BASE, storage });
		const { deviceCode, userCode } = await mod.requestCode();
		const keys = (await storage.list?.("")) ?? [];
		expect(keys.length).toBeGreaterThan(0);
		for (const k of keys) {
			expect(k).not.toContain(deviceCode);
			expect(k).not.toContain(userCode.replace("-", ""));
			expect(await storage.get(k)).not.toContain(deviceCode);
		}
		const hash = await sha256(deviceCode);
		expect(keys.some((k) => k.includes(hash))).toBe(true);
	});

	it("state survives a new module instance on the same storage", async () => {
		const storage = memoryStorage();
		const a = createDeviceAuthModule({ ...BASE, storage });
		const { deviceCode, userCode } = await a.requestCode();
		const b = createDeviceAuthModule({ ...BASE, storage });
		await b.authorize(userCode, "u1");
		expect((await a.checkAuthorization(deviceCode)).status).toBe("authorized");
	});
});

describe("verification_uri_complete", () => {
	it("keeps existing query params and appends user_code", async () => {
		const mod = createDeviceAuthModule({ ...BASE, verificationUri: "https://a.com/d?tenant=1" });
		const r = await mod.requestCode();
		const u = new URL(r.verificationUriComplete);
		expect(u.searchParams.get("tenant")).toBe("1");
		expect(u.searchParams.get("user_code")).toBe(r.userCode);
	});
});

describe("user code attempt limit", () => {
	it("locks an approver out after repeated wrong codes, even for the right one", async () => {
		const mod = createDeviceAuthModule({ ...BASE, userCodeAttemptLimit: 3 });
		const { userCode } = await mod.requestCode();
		for (let i = 0; i < 3; i++)
			await expect(mod.authorize("BBBB-CCCC", "mallory")).rejects.toThrow("not found");
		await expect(mod.authorize(userCode, "mallory")).rejects.toMatchObject({
			code: "too_many_attempts",
		});
		// another user is unaffected
		await expect(mod.authorize(userCode, "alice")).resolves.toBeUndefined();
	});

	it("maps to 429 over HTTP", async () => {
		const mod = createDeviceAuthModule({
			...BASE,
			userCodeAttemptLimit: 1,
			resolveUser: async () => ({ id: "m" }),
		});
		await mod.handleRequest(jsonReq("/auth/device/authorize", { user_code: "BBBB-CCCC" }));
		const res = await mod.handleRequest(
			jsonReq("/auth/device/authorize", { user_code: "BBBB-CCCC" }),
		);
		expect(res?.status).toBe(429);
	});
});

describe("approval endpoint identity", () => {
	it("401s without a session and ignores a user_id in the body", async () => {
		const mod = createDeviceAuthModule(BASE);
		const { userCode, deviceCode } = await mod.requestCode();
		const res = await mod.handleRequest(
			jsonReq("/auth/device/authorize", { user_code: userCode, user_id: "victim" }),
		);
		expect(res?.status).toBe(401);
		expect((await mod.checkAuthorization(deviceCode)).status).toBe("pending");
	});

	it("approves as the session user, not the body user_id", async () => {
		const mod = createDeviceAuthModule({ ...BASE, resolveUser: async () => ({ id: "real-user" }) });
		const { userCode, deviceCode } = await mod.requestCode();
		const res = await mod.handleRequest(
			jsonReq("/auth/device/authorize", { user_code: userCode, user_id: "victim" }),
		);
		expect(res?.status).toBe(200);
		expect(await mod.checkAuthorization(deviceCode)).toEqual({
			status: "authorized",
			userId: "real-user",
		});
	});

	it("rejects cross-origin and non-JSON approvals (CSRF)", async () => {
		const mod = createDeviceAuthModule({ ...BASE, resolveUser: async () => ({ id: "u" }) });
		const { userCode } = await mod.requestCode();
		const cross = await mod.handleRequest(
			jsonReq(
				"/auth/device/authorize",
				{ user_code: userCode },
				{ origin: "https://evil.example" },
			),
		);
		expect(cross?.status).toBe(403);
		const form = await mod.handleRequest(
			new Request("https://app.example.com/auth/device/authorize", {
				method: "POST",
				headers: { "content-type": "application/x-www-form-urlencoded" },
				body: `user_code=${userCode}`,
			}),
		);
		expect(form?.status).toBe(400);
		const same = await mod.handleRequest(
			jsonReq(
				"/auth/device/authorize",
				{ user_code: userCode },
				{ origin: "https://app.example.com" },
			),
		);
		expect(same?.status).toBe(200);
	});
});

describe("token endpoint", () => {
	const poll = (mod: ReturnType<typeof createDeviceAuthModule>, deviceCode: string) =>
		mod.handleRequest(
			jsonReq("/auth/device/token", {
				device_code: deviceCode,
				grant_type: "urn:ietf:params:oauth:grant-type:device_code",
			}),
		);

	it("persists slow_down and raises the interval", async () => {
		vi.useFakeTimers();
		const storage = memoryStorage();
		const mod = createDeviceAuthModule({ ...BASE, storage });
		const { deviceCode } = await mod.requestCode();
		expect(((await (await poll(mod, deviceCode))?.json()) as { error: string }).error).toBe(
			"authorization_pending",
		);
		const fast = (await (await poll(mod, deviceCode))?.json()) as {
			error: string;
			interval: number;
		};
		expect(fast).toMatchObject({ error: "slow_down", interval: 10 });
		// a different module instance on the same storage sees the new interval
		const other = createDeviceAuthModule({ ...BASE, storage });
		vi.advanceTimersByTime(5_000);
		expect(((await (await poll(other, deviceCode))?.json()) as { error: string }).error).toBe(
			"authorization_pending",
		);
		const again = (await (await poll(other, deviceCode))?.json()) as { interval: number };
		expect(again.interval).toBe(15);
		vi.useRealTimers();
	});

	it("rejects a wrong grant_type", async () => {
		const mod = createDeviceAuthModule(BASE);
		const res = await mod.handleRequest(
			jsonReq("/auth/device/token", { device_code: "x", grant_type: "password" }),
		);
		expect(((await res?.json()) as { error: string }).error).toBe("unsupported_grant_type");
	});

	it("issues a token exactly once", async () => {
		vi.useFakeTimers();
		const issueToken = vi.fn(async (userId: string) => ({
			accessToken: `tok-${userId}`,
			expiresIn: 60,
		}));
		const mod = createDeviceAuthModule({ ...BASE, issueToken });
		const { deviceCode, userCode } = await mod.requestCode({ clientId: "cli" });
		await mod.authorize(userCode, "u1");
		const first = (await (await poll(mod, deviceCode))?.json()) as {
			access_token: string;
			token_type: string;
		};
		expect(first).toMatchObject({ access_token: "tok-u1", token_type: "Bearer" });
		vi.advanceTimersByTime(6_000);
		const second = (await (await poll(mod, deviceCode))?.json()) as { error: string };
		expect(second.error).toBe("expired_token");
		expect(issueToken).toHaveBeenCalledTimes(1);
		expect(issueToken).toHaveBeenCalledWith("u1", { clientId: "cli", scope: undefined });
		vi.useRealTimers();
	});

	it("denied codes report access_denied", async () => {
		const mod = createDeviceAuthModule(BASE);
		const { deviceCode, userCode } = await mod.requestCode();
		await mod.deny(userCode, "u1");
		expect(((await (await poll(mod, deviceCode))?.json()) as { error: string }).error).toBe(
			"access_denied",
		);
	});
});

describe("plugin end to end", () => {
	it("approves with a real session and hands the CLI a working session token", async () => {
		const events: string[] = [];
		const auth = await createTheAuth({
			database: { provider: "sqlite", url: ":memory:" },
			auth: { session: { secret: SECRET } },
			secondaryStorage: "database",
			plugins: [
				deviceAuth({
					verificationUri: "https://app.example.com/device",
					onEvent: (e) => void events.push(e.type),
				}),
			],
		});
		auth.db
			.insert(schema.users)
			.values({ id: "u1", email: "a@b.c", name: "A", createdAt: new Date(), updatedAt: new Date() })
			.run();
		const { token: browserToken } = await auth.auth.session!.create("u1");

		const code = (await (await auth.plugins.handleRequest(
			jsonReq("/auth/device/code", { client_id: "cli" }),
		))!.json()) as { device_code: string; user_code: string };

		const anon = await auth.plugins.handleRequest(
			jsonReq("/auth/device/authorize", { user_code: code.user_code, user_id: "u1" }),
		);
		expect(anon?.status).toBe(401);

		const ok = await auth.plugins.handleRequest(
			jsonReq(
				"/auth/device/authorize",
				{ user_code: code.user_code },
				{ authorization: `Bearer ${browserToken}` },
			),
		);
		expect(ok?.status).toBe(200);

		const tok = (await (await auth.plugins.handleRequest(
			jsonReq("/auth/device/token", { device_code: code.device_code }),
		))!.json()) as { access_token: string; user_id: string };
		expect(tok.user_id).toBe("u1");
		const session = await auth.auth.session!.validate(tok.access_token);
		expect(session?.userId).toBe("u1");
		expect(events).toEqual(["device.code_issued", "device.approved", "device.token_issued"]);
		// the hash of the device code is what sits in the database
		const hash = await sha256(code.device_code);
		const rows = await auth.db.select().from(schema.secondaryStorageEntries);
		expect(rows.some((r) => r.storageKey.includes(hash))).toBe(true);
		expect(rows.some((r) => r.storageKey.includes(code.device_code))).toBe(false);
	});
});
