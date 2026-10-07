import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import type { FederationConfig, FederationWellKnown } from "../src/auth/federation.js";
import { createFederationModule } from "../src/auth/federation.js";
import { generateDidKey } from "../src/did/key-method.js";
import { createVCIssuer } from "../src/vc/issuer.js";

// ─── Test Helpers ───────────────────────────────────────────────────────────

async function createTestInstance(overrides?: Partial<FederationConfig>) {
	const { publicKey, privateKey } = await generateKeyPair("EdDSA", { extractable: true });
	const _publicJwk = await exportJWK(publicKey);
	// Strip private parts from publicJwk for sharing
	const { d: _d, ...publicOnlyJwk } = await exportJWK(privateKey);

	const config: FederationConfig = {
		instanceId: `instance-${Math.random().toString(36).slice(2, 8)}`,
		instanceUrl: "https://a.example.com",
		signingKey: privateKey,
		...overrides,
	};

	const federation = createFederationModule(config);
	return { federation, config, publicKey, privateKey, publicJwk: publicOnlyJwk };
}

async function createTwoInstances() {
	const instanceA = await createTestInstance({
		instanceId: "instance-a",
		instanceUrl: "https://a.example.com",
	});
	const instanceB = await createTestInstance({
		instanceId: "instance-b",
		instanceUrl: "https://b.example.com",
	});

	// Cross-trust: A trusts B and B trusts A
	instanceA.federation.addTrustedInstance({
		instanceId: "instance-b",
		instanceUrl: "https://b.example.com",
		publicKey: instanceB.publicJwk,
		trustLevel: "full",
	});
	instanceB.federation.addTrustedInstance({
		instanceId: "instance-a",
		instanceUrl: "https://a.example.com",
		publicKey: instanceA.publicJwk,
		trustLevel: "full",
	});

	return { instanceA, instanceB };
}

// ─── Token Issuance ─────────────────────────────────────────────────────────

describe("federation – token issuance", () => {
	it("issues a federation token for an agent", async () => {
		const { federation } = await createTestInstance();
		const result = await federation.issueFederationToken({
			agentId: "agent-1",
			permissions: ["read:data"],
			trustScore: 0.8,
		});

		expect(result.success).toBe(true);
		if (!result.success) return;

		expect(result.data.token).toBeTruthy();
		expect(result.data.token.split(".")).toHaveLength(3);
		expect(result.data.agentId).toBe("agent-1");
		expect(result.data.expiresAt).toBeInstanceOf(Date);
		expect(result.data.expiresAt.getTime()).toBeGreaterThan(Date.now());
	});

	it("includes source instance in the token", async () => {
		const { federation } = await createTestInstance({
			instanceId: "my-instance",
		});
		const result = await federation.issueFederationToken({
			agentId: "agent-1",
		});

		expect(result.success).toBe(true);
		if (!result.success) return;
		expect(result.data.sourceInstance).toBe("my-instance");
	});

	it("sets audience when targetInstance is provided", async () => {
		const { federation } = await createTestInstance();
		const result = await federation.issueFederationToken({
			agentId: "agent-1",
			targetInstance: "instance-b",
		});

		expect(result.success).toBe(true);
		if (!result.success) return;

		// Decode the JWT to check audience
		const parts = result.data.token.split(".");
		const payload = JSON.parse(atob(parts[1]!.replace(/-/g, "+").replace(/_/g, "/")));
		expect(payload.aud).toBe("instance-b");
	});

	it("rejects empty agentId", async () => {
		const { federation } = await createTestInstance();
		const result = await federation.issueFederationToken({
			agentId: "",
		});

		expect(result.success).toBe(false);
		if (result.success) return;
		expect(result.error.code).toBe("FEDERATION_INVALID_INPUT");
	});

	it("rejects trustScore outside 0-1 range", async () => {
		const { federation } = await createTestInstance();
		const result = await federation.issueFederationToken({
			agentId: "agent-1",
			trustScore: 1.5,
		});

		expect(result.success).toBe(false);
		if (result.success) return;
		expect(result.error.code).toBe("FEDERATION_INVALID_INPUT");
	});

	it("respects custom tokenTtlSeconds", async () => {
		const { federation } = await createTestInstance({ tokenTtlSeconds: 60 });
		const result = await federation.issueFederationToken({
			agentId: "agent-1",
		});

		expect(result.success).toBe(true);
		if (!result.success) return;

		const diffMs = result.data.expiresAt.getTime() - Date.now();
		// Should be roughly 60 seconds (give 5 seconds leeway)
		expect(diffMs).toBeLessThanOrEqual(60_000);
		expect(diffMs).toBeGreaterThan(55_000);
	});

	it("includes permissions and trust score in token payload", async () => {
		const { federation } = await createTestInstance();
		const result = await federation.issueFederationToken({
			agentId: "agent-1",
			permissions: ["read:data", "write:data"],
			trustScore: 0.9,
			delegationScope: ["tool:github"],
		});

		expect(result.success).toBe(true);
		if (!result.success) return;

		const parts = result.data.token.split(".");
		const payload = JSON.parse(atob(parts[1]!.replace(/-/g, "+").replace(/_/g, "/")));
		expect(payload.permissions).toEqual(["read:data", "write:data"]);
		expect(payload.trust_score).toBe(0.9);
		expect(payload.delegation_scope).toEqual(["tool:github"]);
	});

	it("defaults trustScore to 0 and permissions to empty", async () => {
		const { federation } = await createTestInstance();
		const result = await federation.issueFederationToken({
			agentId: "agent-1",
		});

		expect(result.success).toBe(true);
		if (!result.success) return;

		const parts = result.data.token.split(".");
		const payload = JSON.parse(atob(parts[1]!.replace(/-/g, "+").replace(/_/g, "/")));
		expect(payload.permissions).toEqual([]);
		expect(payload.trust_score).toBe(0);
	});
});

// ─── Token Verification ─────────────────────────────────────────────────────

describe("federation – token verification", () => {
	it("verifies a valid token from a trusted instance", async () => {
		const { instanceA, instanceB } = await createTwoInstances();

		const issued = await instanceA.federation.issueFederationToken({
			agentId: "agent-1",
			permissions: ["read:data"],
			trustScore: 0.85,
		});
		expect(issued.success).toBe(true);
		if (!issued.success) return;

		const verified = await instanceB.federation.verifyFederationToken(issued.data.token);

		expect(verified.success).toBe(true);
		if (!verified.success) return;

		expect(verified.data.agentId).toBe("agent-1");
		expect(verified.data.sourceInstance).toBe("instance-a");
		expect(verified.data.permissions).toEqual(["read:data"]);
		expect(verified.data.trustScore).toBe(0.85);
		expect(verified.data.verifiedAt).toBeInstanceOf(Date);
	});

	it("rejects a token from an untrusted instance", async () => {
		const instanceA = await createTestInstance({
			instanceId: "instance-a",
		});
		const instanceB = await createTestInstance({
			instanceId: "instance-b",
		});
		// B does NOT trust A

		const issued = await instanceA.federation.issueFederationToken({
			agentId: "agent-1",
		});
		expect(issued.success).toBe(true);
		if (!issued.success) return;

		const verified = await instanceB.federation.verifyFederationToken(issued.data.token);

		expect(verified.success).toBe(false);
		if (verified.success) return;
		expect(verified.error.code).toBe("FEDERATION_UNTRUSTED_INSTANCE");
	});

	it("rejects an expired token", async () => {
		const { instanceA, instanceB } = await createTwoInstances();

		// Create a token that expired 10 seconds ago
		const now = Math.floor(Date.now() / 1000);
		const expiredToken = await new SignJWT({
			theauth_instance: "instance-a",
			theauth_instance_url: "https://a.example.com",
			permissions: [],
			trust_score: 0,
			delegation_scope: [],
		})
			.setProtectedHeader({ alg: "EdDSA", typ: "theauth-federation+jwt" })
			.setIssuer("instance-a")
			.setSubject("agent-1")
			.setIssuedAt(now - 600)
			.setExpirationTime(now - 10)
			.setJti("expired-jti")
			.sign(instanceA.privateKey);

		const verified = await instanceB.federation.verifyFederationToken(expiredToken);

		expect(verified.success).toBe(false);
		if (verified.success) return;
		expect(verified.error.code).toBe("FEDERATION_TOKEN_EXPIRED");
	});

	it("rejects an empty token", async () => {
		const { federation } = await createTestInstance();
		const result = await federation.verifyFederationToken("");

		expect(result.success).toBe(false);
		if (result.success) return;
		expect(result.error.code).toBe("FEDERATION_INVALID_TOKEN");
	});

	it("rejects a malformed token", async () => {
		const { federation } = await createTestInstance();
		const result = await federation.verifyFederationToken("not.a.jwt.at.all");

		expect(result.success).toBe(false);
		if (result.success) return;
		// Could be UNTRUSTED_INSTANCE or INVALID_TOKEN depending on decode result
		expect(result.success).toBe(false);
	});

	it("rejects a token with wrong audience", async () => {
		const { instanceA, instanceB } = await createTwoInstances();

		const issued = await instanceA.federation.issueFederationToken({
			agentId: "agent-1",
			targetInstance: "instance-c", // Not instance-b
		});
		expect(issued.success).toBe(true);
		if (!issued.success) return;

		const verified = await instanceB.federation.verifyFederationToken(issued.data.token);

		expect(verified.success).toBe(false);
		if (verified.success) return;
		expect(verified.error.code).toBe("FEDERATION_AUDIENCE_MISMATCH");
	});

	it("accepts a token with matching audience", async () => {
		const { instanceA, instanceB } = await createTwoInstances();

		const issued = await instanceA.federation.issueFederationToken({
			agentId: "agent-1",
			targetInstance: "instance-b",
		});
		expect(issued.success).toBe(true);
		if (!issued.success) return;

		const verified = await instanceB.federation.verifyFederationToken(issued.data.token);

		expect(verified.success).toBe(true);
	});
});

// ─── Trust Level Behavior ───────────────────────────────────────────────────

describe("federation – trust levels", () => {
	it("full trust preserves all permissions and trust score", async () => {
		const { instanceA, instanceB } = await createTwoInstances();

		const issued = await instanceA.federation.issueFederationToken({
			agentId: "agent-1",
			permissions: ["read:data", "write:data", "admin:users"],
			trustScore: 0.95,
		});
		expect(issued.success).toBe(true);
		if (!issued.success) return;

		const verified = await instanceB.federation.verifyFederationToken(issued.data.token);
		expect(verified.success).toBe(true);
		if (!verified.success) return;

		expect(verified.data.permissions).toEqual(["read:data", "write:data", "admin:users"]);
		expect(verified.data.trustScore).toBe(0.95);
	});

	it("limited trust strips write and admin permissions", async () => {
		const instanceA = await createTestInstance({
			instanceId: "instance-a",
			instanceUrl: "https://a.example.com",
		});
		const instanceB = await createTestInstance({
			instanceId: "instance-b",
			instanceUrl: "https://b.example.com",
		});

		// B trusts A with limited trust
		instanceB.federation.addTrustedInstance({
			instanceId: "instance-a",
			instanceUrl: "https://a.example.com",
			publicKey: instanceA.publicJwk,
			trustLevel: "limited",
		});

		const issued = await instanceA.federation.issueFederationToken({
			agentId: "agent-1",
			permissions: ["read:data", "write:data", "admin:users", "execute:tools"],
			trustScore: 0.95,
		});
		expect(issued.success).toBe(true);
		if (!issued.success) return;

		const verified = await instanceB.federation.verifyFederationToken(issued.data.token);
		expect(verified.success).toBe(true);
		if (!verified.success) return;

		// write and admin should be stripped
		expect(verified.data.permissions).toEqual(["read:data", "execute:tools"]);
		// Trust score capped at 0.5 for limited
		expect(verified.data.trustScore).toBe(0.5);
	});

	it("verify-only trust strips all permissions and zeroes trust", async () => {
		const instanceA = await createTestInstance({
			instanceId: "instance-a",
			instanceUrl: "https://a.example.com",
		});
		const instanceB = await createTestInstance({
			instanceId: "instance-b",
			instanceUrl: "https://b.example.com",
		});

		instanceB.federation.addTrustedInstance({
			instanceId: "instance-a",
			instanceUrl: "https://a.example.com",
			publicKey: instanceA.publicJwk,
			trustLevel: "verify-only",
		});

		const issued = await instanceA.federation.issueFederationToken({
			agentId: "agent-1",
			permissions: ["read:data", "write:data"],
			trustScore: 0.85,
		});
		expect(issued.success).toBe(true);
		if (!issued.success) return;

		const verified = await instanceB.federation.verifyFederationToken(issued.data.token);
		expect(verified.success).toBe(true);
		if (!verified.success) return;

		expect(verified.data.permissions).toEqual([]);
		expect(verified.data.trustScore).toBe(0);
		expect(verified.data.agentId).toBe("agent-1"); // Identity still verified
	});

	it("limited trust caps trust score at 0.5 even for lower values", async () => {
		const instanceA = await createTestInstance({
			instanceId: "instance-a",
			instanceUrl: "https://a.example.com",
		});
		const instanceB = await createTestInstance({
			instanceId: "instance-b",
			instanceUrl: "https://b.example.com",
		});

		instanceB.federation.addTrustedInstance({
			instanceId: "instance-a",
			instanceUrl: "https://a.example.com",
			publicKey: instanceA.publicJwk,
			trustLevel: "limited",
		});

		const issued = await instanceA.federation.issueFederationToken({
			agentId: "agent-1",
			trustScore: 0.3, // Already below 0.5
		});
		expect(issued.success).toBe(true);
		if (!issued.success) return;

		const verified = await instanceB.federation.verifyFederationToken(issued.data.token);
		expect(verified.success).toBe(true);
		if (!verified.success) return;

		expect(verified.data.trustScore).toBe(0.3); // min(0.3, 0.5) = 0.3
	});
});

// ─── Trust Management ───────────────────────────────────────────────────────

describe("federation – trust management", () => {
	it("adds a trusted instance", async () => {
		const { federation } = await createTestInstance();

		const result = federation.addTrustedInstance({
			instanceId: "new-instance",
			instanceUrl: "https://new.example.com",
			trustLevel: "full",
		});

		expect(result.success).toBe(true);
		const instances = federation.listTrustedInstances();
		expect(instances).toHaveLength(1);
		expect(instances[0]!.instanceId).toBe("new-instance");
	});

	it("removes a trusted instance", async () => {
		const { federation } = await createTestInstance({
			trustedInstances: [
				{
					instanceId: "existing",
					instanceUrl: "https://existing.example.com",
				},
			],
		});

		expect(federation.listTrustedInstances()).toHaveLength(1);

		const result = federation.removeTrustedInstance("existing");
		expect(result.success).toBe(true);
		expect(federation.listTrustedInstances()).toHaveLength(0);
	});

	it("returns error when removing non-existent instance", async () => {
		const { federation } = await createTestInstance();

		const result = federation.removeTrustedInstance("non-existent");
		expect(result.success).toBe(false);
		if (result.success) return;
		expect(result.error.code).toBe("FEDERATION_INSTANCE_NOT_FOUND");
	});

	it("lists trusted instances", async () => {
		const { federation } = await createTestInstance({
			trustedInstances: [
				{
					instanceId: "inst-1",
					instanceUrl: "https://1.example.com",
					trustLevel: "full",
				},
				{
					instanceId: "inst-2",
					instanceUrl: "https://2.example.com",
					trustLevel: "limited",
				},
			],
		});

		const instances = federation.listTrustedInstances();
		expect(instances).toHaveLength(2);
		const ids = instances.map((i) => i.instanceId);
		expect(ids).toContain("inst-1");
		expect(ids).toContain("inst-2");
	});

	it("overwrites an existing trusted instance on re-add", async () => {
		const { federation } = await createTestInstance();

		federation.addTrustedInstance({
			instanceId: "inst",
			instanceUrl: "https://old.example.com",
			trustLevel: "limited",
		});

		federation.addTrustedInstance({
			instanceId: "inst",
			instanceUrl: "https://new.example.com",
			trustLevel: "full",
		});

		const instances = federation.listTrustedInstances();
		expect(instances).toHaveLength(1);
		expect(instances[0]!.instanceUrl).toBe("https://new.example.com");
		expect(instances[0]!.trustLevel).toBe("full");
	});

	it("rejects invalid instance data", async () => {
		const { federation } = await createTestInstance();

		const result = federation.addTrustedInstance({
			instanceId: "",
			instanceUrl: "not-a-url",
		});

		expect(result.success).toBe(false);
	});

	it("preserves pre-configured trusted instances", async () => {
		const { federation } = await createTestInstance({
			trustedInstances: [
				{
					instanceId: "preconfig",
					instanceUrl: "https://preconfig.example.com",
					trustLevel: "full",
				},
			],
		});

		expect(federation.listTrustedInstances()).toHaveLength(1);
		expect(federation.listTrustedInstances()[0]!.instanceId).toBe("preconfig");
	});
});

// ─── Instance Identity ──────────────────────────────────────────────────────

describe("federation – instance identity", () => {
	it("returns correct instance identity", async () => {
		const { federation } = await createTestInstance({
			instanceId: "my-instance",
			instanceUrl: "https://my.example.com",
		});

		const identity = await federation.getInstanceIdentity();

		expect(identity.instanceId).toBe("my-instance");
		expect(identity.instanceUrl).toBe("https://my.example.com");
		expect(identity.publicKeyJwk).toBeTruthy();
		expect(identity.publicKeyJwk.kty).toBe("OKP"); // EdDSA uses OKP
		expect(identity.protocolVersion).toBe("1.0");
		expect(identity.features).toContain("federation-tokens");
	});

	it("does not expose private key material", async () => {
		const { federation } = await createTestInstance();
		const identity = await federation.getInstanceIdentity();

		expect(identity.publicKeyJwk.d).toBeUndefined();
	});
});

// ─── Discovery ──────────────────────────────────────────────────────────────

describe("federation – instance discovery", () => {
	it("discovers an instance via well-known URL", async () => {
		const remoteIdentity = await createTestInstance({
			instanceId: "remote",
			instanceUrl: "https://remote.example.com",
		});

		const wellKnown: FederationWellKnown = {
			instanceId: "remote",
			instanceUrl: "https://remote.example.com",
			publicKeyJwk: remoteIdentity.publicJwk,
			protocolVersion: "1.0",
			features: ["federation-tokens"],
		};

		const mockFetch = async (url: string | URL | Request) => {
			const urlStr = typeof url === "string" ? url : url instanceof URL ? url.href : url.url;
			if (urlStr.includes("/.well-known/theauth-federation.json")) {
				return new Response(JSON.stringify(wellKnown), {
					status: 200,
					headers: { "Content-Type": "application/json" },
				});
			}
			return new Response("Not Found", { status: 404 });
		};

		const { federation } = await createTestInstance();
		const result = await federation.discoverInstance("https://remote.example.com", mockFetch);

		expect(result.success).toBe(true);
		if (!result.success) return;

		expect(result.data.instanceId).toBe("remote");
		expect(result.data.publicKey).toBeTruthy();
		expect(result.data.trustLevel).toBe("verify-only"); // Discovery defaults to verify-only
	});

	it("handles discovery failure (404)", async () => {
		const mockFetch = async () => new Response("Not Found", { status: 404 });

		const { federation } = await createTestInstance();
		const result = await federation.discoverInstance("https://unknown.example.com", mockFetch);

		expect(result.success).toBe(false);
		if (result.success) return;
		expect(result.error.code).toBe("FEDERATION_DISCOVERY_FAILED");
	});

	it("handles discovery failure (network error)", async () => {
		const mockFetch = async () => {
			throw new Error("Network error");
		};

		const { federation } = await createTestInstance();
		const result = await federation.discoverInstance("https://unreachable.example.com", mockFetch);

		expect(result.success).toBe(false);
		if (result.success) return;
		expect(result.error.code).toBe("FEDERATION_DISCOVERY_FAILED");
	});

	it("handles invalid well-known document", async () => {
		const mockFetch = async () =>
			new Response(JSON.stringify({ foo: "bar" }), {
				status: 200,
				headers: { "Content-Type": "application/json" },
			});

		const { federation } = await createTestInstance();
		const result = await federation.discoverInstance("https://bad.example.com", mockFetch);

		expect(result.success).toBe(false);
		if (result.success) return;
		expect(result.error.code).toBe("FEDERATION_DISCOVERY_INVALID");
	});

	it("strips trailing slash from URL before appending well-known path", async () => {
		let requestedUrl = "";
		const mockFetch = async (url: string | URL | Request) => {
			requestedUrl = typeof url === "string" ? url : url instanceof URL ? url.href : url.url;
			return new Response(
				JSON.stringify({
					instanceId: "test",
					instanceUrl: "https://trailing.example.com",
					publicKeyJwk: { kty: "OKP", crv: "Ed25519", x: "test" },
					protocolVersion: "1.0",
					features: [],
				}),
				{ status: 200 },
			);
		};

		const { federation } = await createTestInstance();
		await federation.discoverInstance("https://trailing.example.com/", mockFetch);

		expect(requestedUrl).toBe("https://trailing.example.com/.well-known/theauth-federation.json");
	});
});

// ─── Auto Trust ─────────────────────────────────────────────────────────────

describe("federation – auto trust mode", () => {
	it("auto-trust still requires a public key", async () => {
		const instanceA = await createTestInstance({
			instanceId: "instance-a",
		});
		const instanceB = await createTestInstance({
			instanceId: "instance-b",
			autoTrust: true,
		});

		const issued = await instanceA.federation.issueFederationToken({
			agentId: "agent-1",
		});
		expect(issued.success).toBe(true);
		if (!issued.success) return;

		// Auto-trust but no key configured
		const verified = await instanceB.federation.verifyFederationToken(issued.data.token);

		expect(verified.success).toBe(false);
		if (verified.success) return;
		expect(verified.error.code).toBe("FEDERATION_NO_PUBLIC_KEY");
	});

	it("auto-trust with key verifies successfully", async () => {
		const instanceA = await createTestInstance({
			instanceId: "instance-a",
			instanceUrl: "https://a.example.com",
		});
		const instanceB = await createTestInstance({
			instanceId: "instance-b",
			instanceUrl: "https://b.example.com",
			autoTrust: true,
		});

		// Add A's key to B (like after a discover call)
		instanceB.federation.addTrustedInstance({
			instanceId: "instance-a",
			instanceUrl: "https://a.example.com",
			publicKey: instanceA.publicJwk,
			trustLevel: "full",
		});

		const issued = await instanceA.federation.issueFederationToken({
			agentId: "agent-1",
			permissions: ["read:stuff"],
			trustScore: 0.7,
		});
		expect(issued.success).toBe(true);
		if (!issued.success) return;

		const verified = await instanceB.federation.verifyFederationToken(issued.data.token);

		expect(verified.success).toBe(true);
		if (!verified.success) return;
		expect(verified.data.agentId).toBe("agent-1");
	});
});

// ─── Round-trip Federation ──────────────────────────────────────────────────

describe("federation – round trip", () => {
	it("issue at A, verify at B, preserves full agent data", async () => {
		const { instanceA, instanceB } = await createTwoInstances();

		const issued = await instanceA.federation.issueFederationToken({
			agentId: "agent-roundtrip",
			permissions: ["read:data", "write:data", "execute:tools"],
			trustScore: 0.92,
			delegationScope: ["tool:github", "tool:slack"],
		});
		expect(issued.success).toBe(true);
		if (!issued.success) return;

		const verified = await instanceB.federation.verifyFederationToken(issued.data.token);
		expect(verified.success).toBe(true);
		if (!verified.success) return;

		expect(verified.data.agentId).toBe("agent-roundtrip");
		expect(verified.data.sourceInstance).toBe("instance-a");
		expect(verified.data.sourceInstanceUrl).toBe("https://a.example.com");
		expect(verified.data.permissions).toEqual(["read:data", "write:data", "execute:tools"]);
		expect(verified.data.trustScore).toBe(0.92);
		expect(verified.data.delegationScope).toEqual(["tool:github", "tool:slack"]);
	});

	it("bidirectional federation: A verifies B's tokens too", async () => {
		const { instanceA, instanceB } = await createTwoInstances();

		const issued = await instanceB.federation.issueFederationToken({
			agentId: "agent-from-b",
			permissions: ["read:stuff"],
		});
		expect(issued.success).toBe(true);
		if (!issued.success) return;

		const verified = await instanceA.federation.verifyFederationToken(issued.data.token);
		expect(verified.success).toBe(true);
		if (!verified.success) return;

		expect(verified.data.agentId).toBe("agent-from-b");
		expect(verified.data.sourceInstance).toBe("instance-b");
	});
});

// ─── Federation with VCs ────────────────────────────────────────────────────

describe("federation – with verifiable credentials", () => {
	it("embeds a VC in the federation token", async () => {
		const { instanceA, instanceB } = await createTwoInstances();

		// Issue a VC for the agent
		const keyPair = await generateDidKey();
		const vcIssuer = createVCIssuer({
			issuerDid: keyPair.did,
			privateKeyJwk: keyPair.privateKeyJwk,
			publicKeyJwk: keyPair.publicKeyJwk,
		});

		const vcResult = await vcIssuer.issueAgentCredential({
			agentId: "agent-vc",
			permissions: ["read:data"],
			trustLevel: 0.9,
		});
		expect(vcResult.success).toBe(true);
		if (!vcResult.success) return;

		// Issue a federation token with the embedded VC
		const issued = await instanceA.federation.issueFederationToken({
			agentId: "agent-vc",
			permissions: ["read:data"],
			trustScore: 0.9,
			credential: vcResult.data.jwt,
		});
		expect(issued.success).toBe(true);
		if (!issued.success) return;

		// Verify at B and check that the VC is present
		const verified = await instanceB.federation.verifyFederationToken(issued.data.token);
		expect(verified.success).toBe(true);
		if (!verified.success) return;

		expect(verified.data.credential).toBeTruthy();
		expect(verified.data.credential).toBe(vcResult.data.jwt);
	});

	it("works without an embedded VC", async () => {
		const { instanceA, instanceB } = await createTwoInstances();

		const issued = await instanceA.federation.issueFederationToken({
			agentId: "agent-no-vc",
			permissions: ["read:data"],
		});
		expect(issued.success).toBe(true);
		if (!issued.success) return;

		const verified = await instanceB.federation.verifyFederationToken(issued.data.token);
		expect(verified.success).toBe(true);
		if (!verified.success) return;

		expect(verified.data.credential).toBeUndefined();
	});
});

// ─── Config Validation ──────────────────────────────────────────────────────

describe("federation – config validation", () => {
	it("throws on invalid config (missing instanceId)", async () => {
		const { privateKey } = await generateKeyPair("EdDSA", { extractable: true });

		expect(() =>
			createFederationModule({
				instanceId: "",
				instanceUrl: "https://test.example.com",
				signingKey: privateKey,
			}),
		).toThrow();
	});

	it("throws on invalid config (bad signingKey)", () => {
		expect(() =>
			createFederationModule({
				instanceId: "test",
				instanceUrl: "https://test.example.com",
				signingKey: "not-a-key" as unknown as CryptoKey,
			}),
		).toThrow();
	});
});

// ─── Edge Cases ─────────────────────────────────────────────────────────────

describe("federation – edge cases", () => {
	it("handles token signed with wrong key", async () => {
		const instanceA = await createTestInstance({
			instanceId: "instance-a",
			instanceUrl: "https://a.example.com",
		});
		const instanceB = await createTestInstance({
			instanceId: "instance-b",
			instanceUrl: "https://b.example.com",
		});
		const rogue = await createTestInstance({
			instanceId: "instance-a", // Impersonating A
		});

		// B trusts A's actual key
		instanceB.federation.addTrustedInstance({
			instanceId: "instance-a",
			instanceUrl: "https://a.example.com",
			publicKey: instanceA.publicJwk,
			trustLevel: "full",
		});

		// Rogue signs a token claiming to be A
		const issued = await rogue.federation.issueFederationToken({
			agentId: "agent-evil",
		});
		expect(issued.success).toBe(true);
		if (!issued.success) return;

		// B should reject it because the signature won't match A's key
		const verified = await instanceB.federation.verifyFederationToken(issued.data.token);
		expect(verified.success).toBe(false);
		if (verified.success) return;
		expect(verified.error.code).toBe("FEDERATION_VERIFY_FAILED");
	});

	it("handles delegation scope in round-trip", async () => {
		const { instanceA, instanceB } = await createTwoInstances();

		const issued = await instanceA.federation.issueFederationToken({
			agentId: "agent-1",
			delegationScope: ["mcp:github", "mcp:slack", "tool:file_read"],
		});
		expect(issued.success).toBe(true);
		if (!issued.success) return;

		const verified = await instanceB.federation.verifyFederationToken(issued.data.token);
		expect(verified.success).toBe(true);
		if (!verified.success) return;

		expect(verified.data.delegationScope).toEqual(["mcp:github", "mcp:slack", "tool:file_read"]);
	});
});
