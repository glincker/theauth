import { describe, expect, it, vi } from "vitest";
import type { SiweConfig } from "../src/auth/siwe.js";
import { createSiweModule } from "../src/auth/siwe.js";
import { memoryStorage } from "../src/storage/index.js";

const BASE_CONFIG: SiweConfig = {
	domain: "example.com",
	uri: "https://example.com",
	statement: "Sign in to Example",
	nonceTtlSeconds: 300,
};

const VALID_ADDRESS = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function _buildAndSign(
	config: SiweConfig,
	address = VALID_ADDRESS,
): Promise<{ message: string; nonce: string }> {
	const mod = createSiweModule(config);
	const nonce = await mod.generateNonce();
	const message = mod.buildMessage(address, nonce, 1);
	return { message, nonce };
}

// ---------------------------------------------------------------------------
// generateNonce
// ---------------------------------------------------------------------------

describe("generateNonce", () => {
	it("returns a hex string", async () => {
		const mod = createSiweModule(BASE_CONFIG);
		const nonce = await mod.generateNonce();
		expect(nonce).toMatch(/^[0-9a-f]+$/);
	});

	it("returns unique nonces on successive calls", async () => {
		const mod = createSiweModule(BASE_CONFIG);
		const [n1, n2, n3] = await Promise.all([
			mod.generateNonce(),
			mod.generateNonce(),
			mod.generateNonce(),
		]);
		expect(new Set([n1, n2, n3]).size).toBe(3);
	});

	it("nonce is at least 16 characters", async () => {
		const mod = createSiweModule(BASE_CONFIG);
		const nonce = await mod.generateNonce();
		expect(nonce.length).toBeGreaterThanOrEqual(16);
	});
});

// ---------------------------------------------------------------------------
// buildMessage
// ---------------------------------------------------------------------------

describe("buildMessage", () => {
	it("contains the domain header", () => {
		const mod = createSiweModule(BASE_CONFIG);
		const msg = mod.buildMessage(VALID_ADDRESS, "abc123", 1);
		expect(msg).toContain("example.com wants you to sign in with your Ethereum account:");
	});

	it("contains the Ethereum address", () => {
		const mod = createSiweModule(BASE_CONFIG);
		const msg = mod.buildMessage(VALID_ADDRESS, "abc123", 1);
		expect(msg).toContain(VALID_ADDRESS);
	});

	it("contains the statement when provided", () => {
		const mod = createSiweModule(BASE_CONFIG);
		const msg = mod.buildMessage(VALID_ADDRESS, "abc123", 1);
		expect(msg).toContain("Sign in to Example");
	});

	it("omits the statement line when not configured", () => {
		const mod = createSiweModule({ domain: "example.com", uri: "https://example.com" });
		const msg = mod.buildMessage(VALID_ADDRESS, "abc123", 1);
		expect(msg).not.toContain("Sign in to");
	});

	it("embeds the nonce", () => {
		const mod = createSiweModule(BASE_CONFIG);
		const msg = mod.buildMessage(VALID_ADDRESS, "unique-nonce-42", 1);
		expect(msg).toContain("Nonce: unique-nonce-42");
	});

	it("embeds the chain ID", () => {
		const mod = createSiweModule(BASE_CONFIG);
		const msg = mod.buildMessage(VALID_ADDRESS, "abc", 137);
		expect(msg).toContain("Chain ID: 137");
	});

	it("defaults to chain ID 1 when not specified", () => {
		const mod = createSiweModule(BASE_CONFIG);
		const msg = mod.buildMessage(VALID_ADDRESS, "abc");
		expect(msg).toContain("Chain ID: 1");
	});

	it("includes a Version: 1 field", () => {
		const mod = createSiweModule(BASE_CONFIG);
		const msg = mod.buildMessage(VALID_ADDRESS, "abc");
		expect(msg).toContain("Version: 1");
	});

	it("includes an Issued At timestamp in ISO 8601 format", () => {
		const mod = createSiweModule(BASE_CONFIG);
		const msg = mod.buildMessage(VALID_ADDRESS, "abc");
		expect(msg).toMatch(/Issued At: \d{4}-\d{2}-\d{2}T/);
	});
});

// ---------------------------------------------------------------------------
// verify — nonce lifecycle
// ---------------------------------------------------------------------------

describe("verify — nonce lifecycle", () => {
	it("succeeds with a valid nonce + message", async () => {
		const mod = createSiweModule(BASE_CONFIG);
		const nonce = await mod.generateNonce();
		const message = mod.buildMessage(VALID_ADDRESS, nonce, 1);
		const result = await mod.verify(message, `0x${"a".repeat(130)}`);
		expect(result.address).toBe(VALID_ADDRESS);
		expect(result.chainId).toBe(1);
	});

	it("consumes the nonce (single-use)", async () => {
		const mod = createSiweModule(BASE_CONFIG);
		const nonce = await mod.generateNonce();
		const message = mod.buildMessage(VALID_ADDRESS, nonce, 1);
		await mod.verify(message, `0x${"a".repeat(130)}`);
		await expect(mod.verify(message, `0x${"a".repeat(130)}`)).rejects.toThrow(
			"Nonce not found or already used",
		);
	});

	it("rejects a nonce that was never issued", async () => {
		const mod = createSiweModule(BASE_CONFIG);
		const message = mod.buildMessage(VALID_ADDRESS, "made-up-nonce", 1);
		await expect(mod.verify(message, `0x${"a".repeat(130)}`)).rejects.toThrow(
			"Nonce not found or already used",
		);
	});

	it("rejects an expired nonce", async () => {
		vi.useFakeTimers();
		const mod = createSiweModule({ ...BASE_CONFIG, nonceTtlSeconds: 1 });
		const nonce = await mod.generateNonce();
		const message = mod.buildMessage(VALID_ADDRESS, nonce, 1);

		vi.advanceTimersByTime(2_000);

		await expect(mod.verify(message, `0x${"a".repeat(130)}`)).rejects.toThrow("Nonce expired");
		vi.useRealTimers();
	});
});

// ---------------------------------------------------------------------------
// verify — message format validation
// ---------------------------------------------------------------------------

describe("verify — message format validation", () => {
	it("rejects a completely malformed message", async () => {
		const mod = createSiweModule(BASE_CONFIG);
		const nonce = await mod.generateNonce();
		await expect(mod.verify(`not a real message ${nonce}`, "0xsig")).rejects.toThrow(
			"Invalid SIWE message format",
		);
	});

	it("rejects when domain does not match config", async () => {
		const mod = createSiweModule(BASE_CONFIG);
		const _nonce = await mod.generateNonce();
		// Build message manually with wrong domain
		const wrongDomainMod = createSiweModule({ ...BASE_CONFIG, domain: "evil.com" });
		// We need a nonce in the verification module too — so use a fresh mod
		const verifyMod = createSiweModule(BASE_CONFIG);
		const verifyNonce = await verifyMod.generateNonce();
		const wrongMessage = wrongDomainMod.buildMessage(VALID_ADDRESS, verifyNonce, 1);
		await expect(verifyMod.verify(wrongMessage, "0xsig")).rejects.toThrow("Domain mismatch");
	});

	it("rejects when URI does not match config", async () => {
		const mod = createSiweModule(BASE_CONFIG);
		const _nonce = await mod.generateNonce();
		const wrongUriMod = createSiweModule({ ...BASE_CONFIG, uri: "https://evil.com" });
		// need the nonce in mod
		const verifyMod = createSiweModule(BASE_CONFIG);
		const verifyNonce = await verifyMod.generateNonce();
		const wrongUriMsg = wrongUriMod.buildMessage(VALID_ADDRESS, verifyNonce, 1);
		await expect(verifyMod.verify(wrongUriMsg, "0xsig")).rejects.toThrow("URI mismatch");
	});

	it("rejects when signature is missing", async () => {
		const mod = createSiweModule(BASE_CONFIG);
		const nonce = await mod.generateNonce();
		const message = mod.buildMessage(VALID_ADDRESS, nonce, 1);
		await expect(mod.verify(message, "")).rejects.toThrow("Signature is required");
	});

	it("calls verifySignature override when provided", async () => {
		const verifySignatureFn = vi.fn().mockResolvedValue(VALID_ADDRESS);
		const mod = createSiweModule({ ...BASE_CONFIG, verifySignature: verifySignatureFn });
		const nonce = await mod.generateNonce();
		const message = mod.buildMessage(VALID_ADDRESS, nonce, 1);
		const result = await mod.verify(message, "0xsig");
		expect(verifySignatureFn).toHaveBeenCalledWith(message, "0xsig");
		expect(result.address).toBe(VALID_ADDRESS);
	});

	it("rejects when verifySignature returns a different address", async () => {
		const verifySignatureFn = vi
			.fn()
			.mockResolvedValue("0x0000000000000000000000000000000000000001");
		const mod = createSiweModule({ ...BASE_CONFIG, verifySignature: verifySignatureFn });
		const nonce = await mod.generateNonce();
		const message = mod.buildMessage(VALID_ADDRESS, nonce, 1);
		await expect(mod.verify(message, "0xsig")).rejects.toThrow("Signature does not match address");
	});
});

// ---------------------------------------------------------------------------
// handleRequest
// ---------------------------------------------------------------------------

describe("handleRequest", () => {
	it("GET /auth/siwe/nonce returns a nonce", async () => {
		const mod = createSiweModule(BASE_CONFIG);
		const req = new Request("https://example.com/auth/siwe/nonce", { method: "GET" });
		const res = await mod.handleRequest(req);
		expect(res).not.toBeNull();
		expect(res?.status).toBe(200);
		const body = await res?.json();
		expect(typeof body.nonce).toBe("string");
	});

	it("POST /auth/siwe/verify returns address on success", async () => {
		const mod = createSiweModule(BASE_CONFIG);
		const nonce = await mod.generateNonce();
		const message = mod.buildMessage(VALID_ADDRESS, nonce, 1);

		const req = new Request("https://example.com/auth/siwe/verify", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ message, signature: `0x${"a".repeat(130)}` }),
		});

		const res = await mod.handleRequest(req);
		expect(res).not.toBeNull();
		expect(res?.status).toBe(200);
		const body = await res?.json();
		expect(body.address).toBe(VALID_ADDRESS);
		expect(body.chainId).toBe(1);
	});

	it("POST /auth/siwe/verify returns 400 when fields are missing", async () => {
		const mod = createSiweModule(BASE_CONFIG);
		const req = new Request("https://example.com/auth/siwe/verify", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({}),
		});
		const res = await mod.handleRequest(req);
		expect(res?.status).toBe(400);
	});

	it("returns null for unrecognised paths", async () => {
		const mod = createSiweModule(BASE_CONFIG);
		const req = new Request("https://example.com/other", { method: "GET" });
		const res = await mod.handleRequest(req);
		expect(res).toBeNull();
	});
});

describe("shared nonce storage", () => {
	const SIG = "0x".padEnd(20, "a");

	it("a nonce issued by one instance redeems exactly once on another", async () => {
		const storage = memoryStorage();
		const a = createSiweModule({ ...BASE_CONFIG, storage });
		const b = createSiweModule({ ...BASE_CONFIG, storage });
		const nonce = await a.generateNonce();
		const message = a.buildMessage(VALID_ADDRESS, nonce, 1);
		await expect(b.verify(message, SIG)).resolves.toMatchObject({ address: VALID_ADDRESS });
		await expect(a.verify(message, SIG)).rejects.toThrow(/already used/);
	});

	it("concurrent redemptions of one nonce succeed once", async () => {
		const storage = memoryStorage();
		const a = createSiweModule({ ...BASE_CONFIG, storage });
		const nonce = await a.generateNonce();
		const message = a.buildMessage(VALID_ADDRESS, nonce, 1);
		const results = await Promise.allSettled([
			a.verify(message, SIG),
			a.verify(message, SIG),
			a.verify(message, SIG),
		]);
		expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
	});
});
