import { beforeEach, describe, expect, it } from "vitest";
import { buildDidDocument, generateDidKey, resolveDidKey } from "../src/did/key-method.js";
import {
	createPresentation,
	signPayload,
	verifyPayload,
	verifyPresentation,
} from "../src/did/signing.js";
import { generateDidWeb, getDidWebUrl } from "../src/did/web-method.js";
import type { TheAuth } from "../src/theauth.js";
import { createTestTheAuth } from "./helpers.js";

// ─── did:key ──────────────────────────────────────────────────────────────────

describe("did:key – key generation", () => {
	it("generates a DID starting with did:key:z", async () => {
		const keyPair = await generateDidKey();
		expect(keyPair.did).toMatch(/^did:key:z/);
	});

	it("returns both public and private key JWKs", async () => {
		const { publicKeyJwk, privateKeyJwk } = await generateDidKey();
		expect(publicKeyJwk.kty).toBe("OKP");
		expect(publicKeyJwk.crv).toBe("Ed25519");
		expect(publicKeyJwk.x).toBeTruthy();
		expect(publicKeyJwk.d).toBeUndefined(); // public key has no 'd'

		expect(privateKeyJwk.kty).toBe("OKP");
		expect(privateKeyJwk.crv).toBe("Ed25519");
		expect(privateKeyJwk.d).toBeTruthy(); // private key has 'd'
	});

	it("DID document has the correct W3C context", async () => {
		const { didDocument } = await generateDidKey();
		expect(didDocument["@context"]).toContain("https://www.w3.org/ns/did/v1");
	});

	it("DID document id matches the generated DID", async () => {
		const { did, didDocument } = await generateDidKey();
		expect(didDocument.id).toBe(did);
		expect(didDocument.controller).toBe(did);
	});

	it("DID document has verification method with JsonWebKey2020 type", async () => {
		const { didDocument } = await generateDidKey();
		expect(didDocument.verificationMethod).toHaveLength(1);
		expect(didDocument.verificationMethod[0]?.type).toBe("JsonWebKey2020");
	});

	it("DID document lists authentication, assertionMethod, capabilityInvocation, capabilityDelegation", async () => {
		const { didDocument } = await generateDidKey();
		expect(didDocument.authentication).toHaveLength(1);
		expect(didDocument.assertionMethod).toHaveLength(1);
		expect(didDocument.capabilityInvocation).toHaveLength(1);
		expect(didDocument.capabilityDelegation).toHaveLength(1);
	});

	it("verification method id is a fragment of the DID", async () => {
		const { did, didDocument } = await generateDidKey();
		const vmId = didDocument.verificationMethod[0]?.id ?? "";
		expect(vmId.startsWith(did)).toBe(true);
		expect(vmId).toContain("#");
	});

	it("two calls produce different DIDs (no determinism from same seed)", async () => {
		const a = await generateDidKey();
		const b = await generateDidKey();
		expect(a.did).not.toBe(b.did);
	});
});

describe("did:key – resolution", () => {
	it("resolves a did:key to a DID document", async () => {
		const { did } = await generateDidKey();
		const doc = resolveDidKey(did);
		expect(doc).not.toBeNull();
		expect(doc?.id).toBe(did);
	});

	it("returns null for non-did:key strings", () => {
		expect(resolveDidKey("did:web:example.com")).toBeNull();
		expect(resolveDidKey("not-a-did")).toBeNull();
	});
});

describe("buildDidDocument", () => {
	it("builds a document with all required fields", async () => {
		const { did, publicKeyJwk } = await generateDidKey();
		const doc = buildDidDocument(did, publicKeyJwk);
		expect(doc.id).toBe(did);
		expect(doc.verificationMethod[0]?.publicKeyJwk).toEqual(publicKeyJwk);
	});
});

// ─── did:web ──────────────────────────────────────────────────────────────────

describe("did:web – generation and URL construction", () => {
	it("generates a DID starting with did:web:", async () => {
		const keyPair = await generateDidWeb({ domain: "auth.example.com" }, "agent-42");
		expect(keyPair.did).toMatch(/^did:web:/);
		expect(keyPair.did).toContain("auth.example.com");
	});

	it("embeds the agentId in the DID", async () => {
		const keyPair = await generateDidWeb({ domain: "auth.example.com" }, "agent-42");
		expect(keyPair.did).toContain("agent-42");
	});

	it("uses path when provided", async () => {
		const keyPair = await generateDidWeb(
			{ domain: "auth.example.com", path: "agents" },
			"agent-42",
		);
		expect(keyPair.did).toBe("did:web:auth.example.com:agents:agent-42");
	});

	it("getDidWebUrl – root DID maps to /.well-known/did.json", () => {
		const url = getDidWebUrl("did:web:example.com");
		expect(url).toBe("https://example.com/.well-known/did.json");
	});

	it("getDidWebUrl – path-based DID maps to /path/did.json", () => {
		const url = getDidWebUrl("did:web:example.com:agents:agent-42");
		expect(url).toBe("https://example.com/agents/agent-42/did.json");
	});

	it("getDidWebUrl – throws for non-did:web identifier", () => {
		expect(() => getDidWebUrl("did:key:z6Mk123")).toThrow();
	});

	it("DID document id matches the generated did:web DID", async () => {
		const keyPair = await generateDidWeb({ domain: "auth.example.com" }, "agent-99");
		expect(keyPair.didDocument.id).toBe(keyPair.did);
	});
});

// ─── Signing and verification ─────────────────────────────────────────────────

describe("signPayload / verifyPayload", () => {
	it("signs and verifies a payload roundtrip", async () => {
		const { did, publicKeyJwk, privateKeyJwk } = await generateDidKey();
		const payload = { action: "read", resource: "file:/tmp/data.csv" };

		const signed = await signPayload(payload, privateKeyJwk, did);

		expect(signed.jws).toBeTruthy();
		expect(signed.issuer).toBe(did);

		const result = await verifyPayload(signed.jws, publicKeyJwk);
		expect(result.valid).toBe(true);
		expect(result.issuer).toBe(did);
		expect(result.payload?.action).toBe("read");
	});

	it("verification fails with a different (wrong) public key", async () => {
		const { did, privateKeyJwk } = await generateDidKey();
		const { publicKeyJwk: wrongKey } = await generateDidKey();

		const signed = await signPayload({ data: "secret" }, privateKeyJwk, did);
		const result = await verifyPayload(signed.jws, wrongKey);

		expect(result.valid).toBe(false);
		expect(result.error).toBeTruthy();
	});

	it("verification fails with a tampered JWS", async () => {
		const { did, publicKeyJwk, privateKeyJwk } = await generateDidKey();
		const signed = await signPayload({ data: "real" }, privateKeyJwk, did);

		// Tamper with the signature portion
		const parts = signed.jws.split(".");
		const tampered = `${parts[0]}.${parts[1]}.invalidsignatureXXXX`;

		const result = await verifyPayload(tampered, publicKeyJwk);
		expect(result.valid).toBe(false);
	});
});

// ─── Presentations ────────────────────────────────────────────────────────────

describe("createPresentation / verifyPresentation", () => {
	it("creates and verifies a presentation JWT roundtrip", async () => {
		const { did, publicKeyJwk, privateKeyJwk } = await generateDidKey();

		const jwt = await createPresentation({
			agentId: "agent-1",
			did,
			privateKeyJwk,
			capabilities: ["read:files", "write:logs"],
		});

		expect(jwt).toBeTruthy();
		expect(jwt.split(".")).toHaveLength(3);

		const result = await verifyPresentation(jwt, publicKeyJwk);
		expect(result.valid).toBe(true);
		expect(result.agentId).toBe("agent-1");
		expect(result.did).toBe(did);
		expect(result.capabilities).toEqual(["read:files", "write:logs"]);
	});

	it("presentation verification fails with wrong public key", async () => {
		const { did, privateKeyJwk } = await generateDidKey();
		const { publicKeyJwk: wrongKey } = await generateDidKey();

		const jwt = await createPresentation({
			agentId: "agent-1",
			did,
			privateKeyJwk,
			capabilities: [],
		});

		const result = await verifyPresentation(jwt, wrongKey);
		expect(result.valid).toBe(false);
	});

	it("uses default expiry of 300 seconds", async () => {
		const { did, publicKeyJwk, privateKeyJwk } = await generateDidKey();

		const before = Math.floor(Date.now() / 1000);
		const jwt = await createPresentation({
			agentId: "agent-1",
			did,
			privateKeyJwk,
			capabilities: [],
		});

		// Decode payload to check exp without verifying (we test verification separately)
		const parts = jwt.split(".");
		const payload = JSON.parse(atob((parts[1] ?? "").replace(/-/g, "+").replace(/_/g, "/"))) as {
			exp: number;
			iat: number;
		};

		expect(payload.exp - payload.iat).toBeCloseTo(300, -1);
		expect(payload.exp).toBeGreaterThan(before + 290);
		void publicKeyJwk; // used only for type check above
	});

	it("respects custom expiresIn", async () => {
		const { did, privateKeyJwk } = await generateDidKey();

		const jwt = await createPresentation({
			agentId: "agent-x",
			did,
			privateKeyJwk,
			capabilities: [],
			expiresIn: 60,
		});

		const parts = jwt.split(".");
		const payload = JSON.parse(atob((parts[1] ?? "").replace(/-/g, "+").replace(/_/g, "/"))) as {
			exp: number;
			iat: number;
		};

		expect(payload.exp - payload.iat).toBeCloseTo(60, -1);
	});
});

// ─── Database integration (DID module) ───────────────────────────────────────

describe("DID module – database storage", () => {
	let theauth: TheAuth;
	let agentId: string;

	beforeEach(async () => {
		theauth = await createTestTheAuth();

		const agent = await theauth.agent.create({
			ownerId: "user-1",
			name: "DID Test Agent",
			type: "autonomous",
			permissions: [],
		});
		agentId = agent.id;
	});

	it("generateKey stores the DID and returns private key", async () => {
		const { agentDid, privateKeyJwk } = await theauth.did.generateKey(agentId);

		expect(agentDid.did).toMatch(/^did:key:z/);
		expect(agentDid.agentId).toBe(agentId);
		expect(agentDid.method).toBe("key");
		expect(agentDid.publicKeyJwk.kty).toBe("OKP");
		expect(privateKeyJwk.d).toBeTruthy(); // private key returned to caller
	});

	it("getAgentDid retrieves the stored DID record", async () => {
		const { agentDid } = await theauth.did.generateKey(agentId);

		const stored = await theauth.did.getAgentDid(agentId);
		expect(stored).not.toBeNull();
		expect(stored?.did).toBe(agentDid.did);
		expect(stored?.method).toBe("key");
		expect(stored?.didDocument.id).toBe(agentDid.did);
	});

	it("getAgentDid returns null when no DID exists", async () => {
		const result = await theauth.did.getAgentDid("nonexistent-agent");
		expect(result).toBeNull();
	});

	it("sign and verify a payload end-to-end via the module", async () => {
		const { agentDid, privateKeyJwk } = await theauth.did.generateKey(agentId);
		const payload = { action: "execute", tool: "search" };

		const signed = await theauth.did.sign(agentId, payload, privateKeyJwk);
		expect(signed.issuer).toBe(agentDid.did);

		const result = await theauth.did.verify(signed.jws, agentDid.did);
		expect(result.valid).toBe(true);
		expect(result.payload?.action).toBe("execute");
	});

	it("verify fails when the DID has no stored key", async () => {
		// Create a signed payload from a standalone key pair (not stored in DB)
		const { did, privateKeyJwk } = await generateDidKey();
		const signed = await signPayload({ x: 1 }, privateKeyJwk, did);

		const result = await theauth.did.verify(signed.jws, did);
		expect(result.valid).toBe(false);
		expect(result.error).toContain("No stored public key");
	});

	it("verify returns error when no DID is provided", async () => {
		const result = await theauth.did.verify("some.jws.value");
		expect(result.valid).toBe(false);
	});

	it("createPresentation and verifyPresentation roundtrip via module", async () => {
		const { agentDid, privateKeyJwk } = await theauth.did.generateKey(agentId);

		const jwt = await theauth.did.createPresentation({
			agentId,
			privateKeyJwk,
			capabilities: ["tool:search", "tool:write"],
		});

		const result = await theauth.did.verifyPresentation(jwt);
		expect(result.valid).toBe(true);
		expect(result.capabilities).toEqual(["tool:search", "tool:write"]);
		expect(result.issuer).toBe(agentDid.did);
	});

	it("generateWeb stores a did:web DID when web config is set", async () => {
		// Create a separate theauth instance with web config
		const [{ createTheAuth }, schema] = await Promise.all([
			import("../src/theauth.js"),
			import("../src/db/schema.js"),
		]);

		const theAuthWithWeb = await createTheAuth({
			database: { provider: "sqlite", url: ":memory:" },
			did: { web: { domain: "auth.example.com", path: "agents" } },
		});

		// Seed a user and agent in this instance
		theAuthWithWeb.db
			.insert(schema.users)
			.values({
				id: "user-w",
				email: "web@example.com",
				createdAt: new Date(),
				updatedAt: new Date(),
			})
			.run();

		const agent = await theAuthWithWeb.agent.create({
			ownerId: "user-w",
			name: "Web DID Agent",
			type: "autonomous",
			permissions: [],
		});

		const { agentDid } = await theAuthWithWeb.did.generateWeb(agent.id);
		expect(agentDid.did).toMatch(/^did:web:auth\.example\.com:agents:/);
		expect(agentDid.method).toBe("web");
	});

	it("generateWeb throws when web config is absent", async () => {
		await expect(theauth.did.generateWeb(agentId)).rejects.toThrow("did:web requires");
	});

	it("resolve delegates to did:key resolver", async () => {
		const { agentDid } = await theauth.did.generateKey(agentId);
		const doc = await theauth.did.resolve(agentDid.did);
		expect(doc).not.toBeNull();
		expect(doc?.id).toBe(agentDid.did);
	});

	it("resolve returns null for unknown methods", async () => {
		const doc = await theauth.did.resolve("did:unknown:abc123");
		expect(doc).toBeNull();
	});
});
