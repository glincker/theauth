import { describe, expect, it, vi } from "vitest";
import { createTheAuthGoClient } from "../src/go-client.js";
import { isRecentAuthRequired, isThrottleError } from "../src/go-errors.js";

interface Reply {
	status: number;
	body?: unknown;
	headers?: Record<string, string>;
}

function res(r: Reply) {
	const text = r.body === undefined ? "" : JSON.stringify(r.body);
	return {
		ok: r.status >= 200 && r.status < 300,
		status: r.status,
		headers: new Headers(r.headers),
		text: () => Promise.resolve(text),
	};
}

function client(...replies: Reply[]) {
	const fetchFn = vi.fn();
	for (const r of replies) fetchFn.mockResolvedValueOnce(res(r));
	return { fetchFn, api: createTheAuthGoClient({ fetch: fetchFn as unknown as typeof fetch }) };
}

function sent(fetchFn: ReturnType<typeof vi.fn>, i = 0) {
	const [url, init] = fetchFn.mock.calls[i] as [string, RequestInit];
	return {
		url,
		method: init.method,
		headers: init.headers as Record<string, string>,
		body: init.body ? JSON.parse(init.body as string) : undefined,
	};
}

describe("sessions", () => {
	it("unwraps the list", async () => {
		const row = {
			id: "s1",
			deviceLabel: "Mac",
			createdAt: "",
			lastSeenAt: "",
			expiresAt: "",
			current: true,
		};
		const { api } = client({ status: 200, body: { sessions: [row] } });
		expect(await api.session.list()).toEqual({ success: true, data: [row] });
	});
	it("revokes others and returns the count", async () => {
		const { api } = client({ status: 200, body: { revoked: 3 } });
		expect(await api.session.revokeOthers()).toEqual({ success: true, data: { revoked: 3 } });
	});
});

describe("step-up and errors", () => {
	it("sends the proof and returns elevatedUntil", async () => {
		const { api, fetchFn } = client({
			status: 200,
			body: { elevatedUntil: "2026-01-01T00:00:00Z" },
		});
		const r = await api.stepUp.verify({ method: "totp", code: "123456" });
		expect(r).toEqual({ success: true, data: { elevatedUntil: "2026-01-01T00:00:00Z" } });
		expect(sent(fetchFn).body).toEqual({ method: "totp", code: "123456" });
	});
	it("recognizes the problem+json recent auth code", async () => {
		const { api } = client({
			status: 403,
			body: {
				type: "x",
				status: 403,
				code: "auth.recent_auth_required",
				message: "m",
				detail: "d",
			},
		});
		const r = await api.apiTokens.revoke("x");
		expect(!r.success && isRecentAuthRequired(r.error)).toBe(true);
	});
	it("types throttle errors with retryAfter", async () => {
		const { api } = client({
			status: 429,
			body: { code: "account_locked", message: "locked" },
			headers: { "Retry-After": "90" },
		});
		const r = await api.login({ email: "a", password: "b" });
		expect(r.success).toBe(false);
		if (!r.success && isThrottleError(r.error)) {
			expect(r.error.code).toBe("account_locked");
			expect(r.error.retryAfter).toBe(90);
		} else throw new Error("expected throttle error");
	});
});

describe("password, bootstrap, setup token", () => {
	it("posts password change", async () => {
		const { api, fetchFn } = client({ status: 204 });
		await api.changePassword({ currentPassword: "a", newPassword: "b" });
		expect(sent(fetchFn)).toMatchObject({ url: "/auth/password/change", method: "POST" });
	});
	it("reads bootstrap status", async () => {
		const { api } = client({ status: 200, body: { needsSetup: true } });
		expect(await api.bootstrap.status()).toEqual({ success: true, data: { needsSetup: true } });
	});
	it("sends the setup token as a header, not in the body", async () => {
		const { api, fetchFn } = client({ status: 200, body: { ok: true } });
		await api.signup({ email: "a", password: "b", setupToken: "tok" });
		const s = sent(fetchFn);
		expect(s.headers["X-Setup-Token"]).toBe("tok");
		expect(s.body).toEqual({ email: "a", password: "b" });
	});
	it("surfaces setup_token_invalid", async () => {
		const { api } = client({ status: 403, body: { code: "setup_token_invalid", message: "m" } });
		const r = await api.signup({ email: "a", password: "b" });
		expect(!r.success && r.error.code).toBe("setup_token_invalid");
	});
});

describe("api tokens", () => {
	it("lists with admin filters", async () => {
		const { api, fetchFn } = client({ status: 200, body: { tokens: [] } });
		await api.apiTokens.list({ all: true });
		expect(sent(fetchFn).url).toBe("/auth/tokens/?all=true");
	});
	it("lists mine with no query", async () => {
		const { api, fetchFn } = client({ status: 200, body: { tokens: [{ id: "t" }] } });
		const r = await api.apiTokens.list();
		expect(sent(fetchFn).url).toBe("/auth/tokens/");
		expect(r.success && r.data).toHaveLength(1);
	});
	it("mints with snake_case wire fields", async () => {
		const { api, fetchFn } = client({ status: 201, body: { token: "raw", id: "t" } });
		const r = await api.apiTokens.mint({
			name: "ci",
			abilities: ["a"],
			expiresIn: 60,
			serviceAccount: true,
			ownerId: "o",
		});
		expect(sent(fetchFn).body).toEqual({
			name: "ci",
			abilities: ["a"],
			expires_in: 60,
			service_account: true,
			owner_id: "o",
		});
		expect(r.success && r.data.token).toBe("raw");
	});
});

describe("device grant", () => {
	it("maps the code response", async () => {
		const { api } = client({
			status: 200,
			body: {
				device_code: "d",
				user_code: "U",
				verification_uri: "v",
				verification_uri_complete: "vc",
				expires_in: 600,
				interval: 5,
			},
		});
		expect(await api.device.code({ clientName: "cli" })).toEqual({
			success: true,
			data: {
				deviceCode: "d",
				userCode: "U",
				verificationUri: "v",
				verificationUriComplete: "vc",
				expiresIn: 600,
				interval: 5,
			},
		});
	});

	it("reads the RFC 8628 error shape", async () => {
		const { api } = client({
			status: 400,
			body: { error: "authorization_pending", error_description: "wait" },
		});
		const r = await api.device.token("d");
		expect(!r.success && r.error).toMatchObject({ code: "authorization_pending", message: "wait" });
	});

	it("polls through pending, backs off on slow_down, then returns the token", async () => {
		const pending = { status: 400, body: { error: "authorization_pending" } };
		const slow = { status: 400, body: { error: "slow_down" } };
		const done = {
			status: 200,
			body: { access_token: "tok", token_type: "Bearer", expires_in: 60, scope: "a b" },
		};
		const { api, fetchFn } = client(pending, slow, pending, done);
		const sleep = vi.fn().mockResolvedValue(undefined);
		const r = await api.device.poll({ deviceCode: "d", interval: 2, sleep });
		expect(r).toEqual({
			success: true,
			data: { accessToken: "tok", tokenType: "Bearer", expiresIn: 60, scope: "a b" },
		});
		expect(sleep.mock.calls.map((c) => c[0])).toEqual([2000, 7000, 7000]);
		expect(sent(fetchFn).body).toEqual({
			grant_type: "urn:ietf:params:oauth:grant-type:device_code",
			device_code: "d",
		});
	});

	it("stops on a terminal error", async () => {
		const { api } = client({ status: 400, body: { error: "access_denied" } });
		const r = await api.device.poll({ deviceCode: "d", sleep: vi.fn() });
		expect(!r.success && r.error.code).toBe("access_denied");
	});

	it("gives up as expired_token once the window passes", async () => {
		const pending = { status: 400, body: { error: "authorization_pending" } };
		const { api } = client(pending, pending, pending);
		const r = await api.device.poll({
			deviceCode: "d",
			interval: 5,
			expiresIn: 10,
			sleep: vi.fn().mockResolvedValue(undefined),
		});
		expect(!r.success && r.error.code).toBe("expired_token");
	});

	it("looks up, approves and denies by user code", async () => {
		const { api, fetchFn } = client(
			{
				status: 200,
				body: {
					client_name: "cli",
					abilities: ["a"],
					requester_ip: "1.1.1.1",
					requester_user_agent: "ua",
					expires_at: "t",
				},
			},
			{ status: 204 },
			{ status: 204 },
		);
		const info = await api.device.info("U-1");
		expect(info.success && info.data).toEqual({
			clientName: "cli",
			abilities: ["a"],
			requesterIp: "1.1.1.1",
			requesterUserAgent: "ua",
			expiresAt: "t",
		});
		await api.device.approve("U-1", ["a"]);
		await api.device.deny("U-1");
		expect(sent(fetchFn, 0).body).toEqual({ action: "info", user_code: "U-1" });
		expect(sent(fetchFn, 1).body).toEqual({
			action: "approve",
			user_code: "U-1",
			abilities: ["a"],
		});
		expect(sent(fetchFn, 2).body).toEqual({ action: "deny", user_code: "U-1" });
	});

	it("types the approval throttle", async () => {
		const { api } = client({
			status: 429,
			body: { error: "rate_limited", error_description: "x" },
			headers: { "Retry-After": "900" },
		});
		const r = await api.device.approve("U-1");
		expect(!r.success && isThrottleError(r.error) && r.error.retryAfter).toBe(900);
	});
});

describe("totp and passkey additions", () => {
	it("reads status and regenerates codes", async () => {
		const { api, fetchFn } = client(
			{ status: 200, body: { enrolled: true, recoveryCodesRemaining: 4 } },
			{ status: 200, body: { recoveryCodes: ["a", "b"] } },
		);
		expect(await api.totp.status()).toEqual({
			success: true,
			data: { enrolled: true, recoveryCodesRemaining: 4 },
		});
		expect(await api.totp.regenerateRecoveryCodes()).toEqual({
			success: true,
			data: { recoveryCodes: ["a", "b"] },
		});
		expect(sent(fetchFn, 0).url).toBe("/auth/totp/");
	});
	it("renames a passkey", async () => {
		const { api, fetchFn } = client({ status: 204 });
		await api.passkeys.rename("id1", "Laptop");
		expect(sent(fetchFn)).toMatchObject({
			url: "/auth/webauthn/credentials/id1",
			method: "PATCH",
			body: { name: "Laptop" },
		});
	});
});
