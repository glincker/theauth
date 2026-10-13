import { describe, expect, it, vi } from "vitest";
import type { DeviceAuthConfig } from "../src/auth/device-auth.js";
import { createDeviceAuthModule } from "../src/auth/device-auth.js";

const BASE_CONFIG: DeviceAuthConfig = {
	verificationUri: "https://example.com/device",
	codeLength: 4,
	codeExpirySeconds: 900,
	pollIntervalSeconds: 5,
};

// requestCode

describe("requestCode", () => {
	it("returns all required RFC 8628 fields", async () => {
		const mod = createDeviceAuthModule(BASE_CONFIG);
		const res = await mod.requestCode();
		expect(typeof res.deviceCode).toBe("string");
		expect(typeof res.userCode).toBe("string");
		expect(res.verificationUri).toBe("https://example.com/device");
		expect(res.expiresIn).toBe(900);
		expect(res.interval).toBe(5);
	});

	it("user code has the XXXX-XXXX format with 4-char segments", async () => {
		const mod = createDeviceAuthModule(BASE_CONFIG);
		const res = await mod.requestCode();
		expect(res.userCode).toMatch(/^[A-Z]{4}-[A-Z]{4}$/);
	});

	it("user code segments contain only consonant-alphabet characters", async () => {
		const mod = createDeviceAuthModule(BASE_CONFIG);
		const res = await mod.requestCode();
		// No vowels (AEIOU) and no digits
		expect(res.userCode.replace("-", "")).toMatch(/^[BCDFGHJKLMNPQRSTVWXZ]+$/);
	});

	it("user code is unique across multiple requests", async () => {
		const mod = createDeviceAuthModule(BASE_CONFIG);
		const codes = await Promise.all(Array.from({ length: 10 }, () => mod.requestCode()));
		const userCodes = codes.map((c) => c.userCode);
		expect(new Set(userCodes).size).toBe(10);
	});

	it("device code is unique across multiple requests", async () => {
		const mod = createDeviceAuthModule(BASE_CONFIG);
		const codes = await Promise.all(Array.from({ length: 5 }, () => mod.requestCode()));
		const deviceCodes = codes.map((c) => c.deviceCode);
		expect(new Set(deviceCodes).size).toBe(5);
	});

	it("verificationUriComplete contains the user_code as query param", async () => {
		const mod = createDeviceAuthModule(BASE_CONFIG);
		const res = await mod.requestCode();
		expect(res.verificationUriComplete).toContain("user_code=");
		expect(res.verificationUriComplete).toContain(encodeURIComponent(res.userCode));
	});
});

// checkAuthorization — initial state

describe("checkAuthorization — initial state", () => {
	it("returns pending for a newly issued code", async () => {
		const mod = createDeviceAuthModule(BASE_CONFIG);
		const { deviceCode } = await mod.requestCode();
		const status = await mod.checkAuthorization(deviceCode);
		expect(status.status).toBe("pending");
	});

	it("returns expired for an unknown device code", async () => {
		const mod = createDeviceAuthModule(BASE_CONFIG);
		const status = await mod.checkAuthorization("completely-made-up-code");
		expect(status.status).toBe("expired");
	});

	it("returns expired after TTL elapses", async () => {
		vi.useFakeTimers();
		const mod = createDeviceAuthModule({ ...BASE_CONFIG, codeExpirySeconds: 1 });
		const { deviceCode } = await mod.requestCode();

		vi.advanceTimersByTime(2_000);

		const status = await mod.checkAuthorization(deviceCode);
		expect(status.status).toBe("expired");
		vi.useRealTimers();
	});
});

// authorize

describe("authorize", () => {
	it("transitions state to authorized and stores the userId", async () => {
		const mod = createDeviceAuthModule(BASE_CONFIG);
		const { deviceCode, userCode } = await mod.requestCode();

		await mod.authorize(userCode, "user-123");

		const status = await mod.checkAuthorization(deviceCode);
		expect(status.status).toBe("authorized");
		if (status.status === "authorized") {
			expect(status.userId).toBe("user-123");
		}
	});

	it("is case-insensitive for the user code", async () => {
		const mod = createDeviceAuthModule(BASE_CONFIG);
		const { deviceCode, userCode } = await mod.requestCode();

		await mod.authorize(userCode.toLowerCase(), "user-456");

		const status = await mod.checkAuthorization(deviceCode);
		expect(status.status).toBe("authorized");
	});

	it("accepts user code with or without the dash separator", async () => {
		const mod = createDeviceAuthModule(BASE_CONFIG);
		const { deviceCode, userCode } = await mod.requestCode();
		const noDash = userCode.replace("-", "");

		await mod.authorize(noDash, "user-789");

		const status = await mod.checkAuthorization(deviceCode);
		expect(status.status).toBe("authorized");
	});

	it("throws when the user code does not exist", async () => {
		const mod = createDeviceAuthModule(BASE_CONFIG);
		await expect(mod.authorize("AAAA-BBBB", "user-x")).rejects.toThrow(
			"User code not found or expired",
		);
	});

	it("throws when attempting to authorize an already-authorized code", async () => {
		const mod = createDeviceAuthModule(BASE_CONFIG);
		const { userCode } = await mod.requestCode();
		await mod.authorize(userCode, "user-1");
		await expect(mod.authorize(userCode, "user-2")).rejects.toThrow("already authorized");
	});
});

// deny

describe("deny", () => {
	it("transitions state to denied", async () => {
		const mod = createDeviceAuthModule(BASE_CONFIG);
		const { deviceCode, userCode } = await mod.requestCode();

		await mod.deny(userCode);

		const status = await mod.checkAuthorization(deviceCode);
		expect(status.status).toBe("denied");
	});

	it("throws when user code does not exist", async () => {
		const mod = createDeviceAuthModule(BASE_CONFIG);
		await expect(mod.deny("AAAA-BBBB")).rejects.toThrow("User code not found or expired");
	});

	it("throws when attempting to deny an already-denied code", async () => {
		const mod = createDeviceAuthModule(BASE_CONFIG);
		const { userCode } = await mod.requestCode();
		await mod.deny(userCode);
		await expect(mod.deny(userCode)).rejects.toThrow("already denied");
	});
});

// handleRequest — POST /auth/device/code

describe("handleRequest — POST /auth/device/code", () => {
	it("returns RFC 8628 snake_case fields", async () => {
		const mod = createDeviceAuthModule(BASE_CONFIG);
		const req = new Request("https://example.com/auth/device/code", { method: "POST" });
		const res = await mod.handleRequest(req);
		expect(res).not.toBeNull();
		expect(res?.status).toBe(200);
		const body = await res?.json();
		expect(typeof body.device_code).toBe("string");
		expect(typeof body.user_code).toBe("string");
		expect(body.verification_uri).toBe("https://example.com/device");
		expect(body.expires_in).toBe(900);
		expect(body.interval).toBe(5);
	});
});

// handleRequest — POST /auth/device/token

describe("handleRequest — POST /auth/device/token", () => {
	it("returns authorization_pending while code is pending", async () => {
		const mod = createDeviceAuthModule(BASE_CONFIG);
		const { deviceCode } = await mod.requestCode();

		const req = new Request("https://example.com/auth/device/token", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ device_code: deviceCode }),
		});

		const res = await mod.handleRequest(req);
		expect(res?.status).toBe(400);
		const body = await res?.json();
		expect(body.error).toBe("authorization_pending");
	});

	it("returns authorized: true once the code is approved", async () => {
		const mod = createDeviceAuthModule(BASE_CONFIG);
		const { deviceCode, userCode } = await mod.requestCode();
		await mod.authorize(userCode, "user-abc");

		const req = new Request("https://example.com/auth/device/token", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ device_code: deviceCode }),
		});

		const res = await mod.handleRequest(req);
		expect(res?.status).toBe(200);
		const body = await res?.json();
		expect(body.authorized).toBe(true);
		expect(body.user_id).toBe("user-abc");
	});

	it("returns access_denied when the code was denied", async () => {
		const mod = createDeviceAuthModule(BASE_CONFIG);
		const { deviceCode, userCode } = await mod.requestCode();
		await mod.deny(userCode);

		const req = new Request("https://example.com/auth/device/token", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ device_code: deviceCode }),
		});

		const res = await mod.handleRequest(req);
		expect(res?.status).toBe(400);
		const body = await res?.json();
		expect(body.error).toBe("access_denied");
	});

	it("returns expired_token for an expired code", async () => {
		vi.useFakeTimers();
		const mod = createDeviceAuthModule({ ...BASE_CONFIG, codeExpirySeconds: 1 });
		const { deviceCode } = await mod.requestCode();
		vi.advanceTimersByTime(2_000);

		const req = new Request("https://example.com/auth/device/token", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ device_code: deviceCode }),
		});

		const res = await mod.handleRequest(req);
		expect(res?.status).toBe(400);
		const body = await res?.json();
		expect(body.error).toBe("expired_token");
		vi.useRealTimers();
	});

	it("returns invalid_request when device_code is absent", async () => {
		const mod = createDeviceAuthModule(BASE_CONFIG);
		const req = new Request("https://example.com/auth/device/token", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({}),
		});
		const res = await mod.handleRequest(req);
		expect(res?.status).toBe(400);
		const body = await res?.json();
		expect(body.error).toBe("invalid_request");
	});
});

// handleRequest — unrecognised paths

describe("handleRequest — unrecognised paths", () => {
	it("returns null for unknown routes", async () => {
		const mod = createDeviceAuthModule(BASE_CONFIG);
		const req = new Request("https://example.com/other", { method: "GET" });
		const res = await mod.handleRequest(req);
		expect(res).toBeNull();
	});
});
