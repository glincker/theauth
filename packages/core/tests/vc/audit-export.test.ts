import { describe, expect, it } from "vitest";
import { generateDidKey } from "../../src/did/key-method.js";
import type { AuditEntry } from "../../src/types.js";
import {
	exportAuditAsVC,
	KAVACHOS_AUDIT_CONTEXT,
	KAVACHOS_AUDIT_CREDENTIAL,
} from "../../src/vc/audit-export.js";
import type { VCIssuerConfig } from "../../src/vc/types.js";
import { VC_CONTEXT_V2 } from "../../src/vc/types.js";
import { createVCVerifier } from "../../src/vc/verifier.js";

// ─── Fixtures ────────────────────────────────────────────────────────────────

const T0 = new Date("2025-06-01T00:00:00Z");
const T2 = new Date("2025-06-01T02:00:00Z");

function makeRecord(
	i: number,
	offsetMs: number,
	result: AuditEntry["result"] = "allowed",
): AuditEntry {
	return {
		id: `audit-${i}`,
		agentId: `agent-${i % 3}`,
		userId: `user-${i % 2}`,
		action: "execute",
		resource: `mcp:tool:${i}`,
		parameters: {},
		result,
		durationMs: 10,
		timestamp: new Date(T0.getTime() + offsetMs),
	};
}

/**
 * Seed 20 records spread across 2 hours (0 to 7200000 ms).
 * Records 0–9 are "allowed", 10–14 are "denied", 15–19 are "rate_limited".
 */
function makeRecords(): AuditEntry[] {
	return Array.from({ length: 20 }, (_, i) => {
		const offsetMs = Math.floor((i / 19) * 7_200_000);
		const result: AuditEntry["result"] = i < 10 ? "allowed" : i < 15 ? "denied" : "rate_limited";
		return makeRecord(i, offsetMs, result);
	});
}

async function makeConfig(): Promise<{ config: VCIssuerConfig; did: string }> {
	const keyPair = await generateDidKey();
	const config: VCIssuerConfig = {
		issuerDid: keyPair.did,
		privateKeyJwk: keyPair.privateKeyJwk,
		publicKeyJwk: keyPair.publicKeyJwk,
	};
	return { config, did: keyPair.did };
}

// ─── Tests ───────────────────────────────────────────────────────────────────

describe("exportAuditAsVC – ldp_vc individual", () => {
	it("returns 20 credentials with correct shape", async () => {
		const { config, did } = await makeConfig();
		const records = makeRecords();

		const result = await exportAuditAsVC({
			since: T0,
			until: T2,
			issuerDid: did,
			issuerConfig: config,
			format: "ldp_vc",
			output: "individual",
			records,
		});

		expect(result.count).toBe(20);
		expect(result.credentials).toHaveLength(20);
		expect(result.format).toBe("ldp_vc");

		const first = result.credentials[0];
		expect(first?.["@context"]).toContain(VC_CONTEXT_V2);
		expect(first?.["@context"]).toContain(KAVACHOS_AUDIT_CONTEXT);
		expect(first?.type).toContain(KAVACHOS_AUDIT_CREDENTIAL);
		expect(first?.proof).toBeDefined();
		expect(first?.proof?.type).toBe("JsonWebSignature2020");
	});

	it("each ldp_vc credential verifies with verifyCredential()", async () => {
		const { config, did } = await makeConfig();
		const records = makeRecords();
		const verifier = createVCVerifier({
			resolveDidKey: async () => config.publicKeyJwk,
		});

		const result = await exportAuditAsVC({
			since: T0,
			until: T2,
			issuerDid: did,
			issuerConfig: config,
			format: "ldp_vc",
			output: "individual",
			records,
		});

		for (const vc of result.credentials) {
			const verified = await verifier.verifyCredential(vc, config.publicKeyJwk);
			expect(verified.success).toBe(true);
		}
	});
});

describe("exportAuditAsVC – jwt_vc individual", () => {
	it("returns 20 JWT strings", async () => {
		const { config, did } = await makeConfig();
		const records = makeRecords();

		const result = await exportAuditAsVC({
			since: T0,
			until: T2,
			issuerDid: did,
			issuerConfig: config,
			format: "jwt_vc",
			output: "individual",
			records,
		});

		expect(result.count).toBe(20);
		expect(result.jwts).toHaveLength(20);

		for (const jwt of result.jwts ?? []) {
			expect(typeof jwt).toBe("string");
			expect(jwt.split(".")).toHaveLength(3);
		}
	});

	it("each jwt_vc verifies with verifyCredential()", async () => {
		const { config, did } = await makeConfig();
		const records = makeRecords();
		const verifier = createVCVerifier({
			resolveDidKey: async () => config.publicKeyJwk,
		});

		const result = await exportAuditAsVC({
			since: T0,
			until: T2,
			issuerDid: did,
			issuerConfig: config,
			format: "jwt_vc",
			output: "individual",
			records,
		});

		for (const jwt of result.jwts ?? []) {
			const verified = await verifier.verifyCredential(jwt, config.publicKeyJwk);
			expect(verified.success).toBe(true);
		}
	});
});

describe("exportAuditAsVC – ldp_vc presentation", () => {
	it("wraps 20 credentials in a single VP", async () => {
		const { config, did } = await makeConfig();
		const records = makeRecords();
		const verifier = createVCVerifier({
			resolveDidKey: async () => config.publicKeyJwk,
		});

		const result = await exportAuditAsVC({
			since: T0,
			until: T2,
			issuerDid: did,
			issuerConfig: config,
			format: "ldp_vc",
			output: "presentation",
			records,
		});

		expect(result.count).toBe(20);
		expect(result.presentation).toBeDefined();

		const vp = result.presentation;
		expect(vp?.verifiableCredential).toHaveLength(20);
		expect(vp?.holder).toBe(did);

		// Verify the presentation
		if (vp) {
			const vpResult = await verifier.verifyPresentation(vp, config.publicKeyJwk);
			expect(vpResult.success).toBe(true);
		}
	});
});

describe("exportAuditAsVC – tamper test", () => {
	it("fails verification after credential content is modified", async () => {
		const { config, did } = await makeConfig();
		const records = [makeRecord(0, 0)];
		const verifier = createVCVerifier({
			resolveDidKey: async () => config.publicKeyJwk,
		});

		const result = await exportAuditAsVC({
			since: T0,
			until: T2,
			issuerDid: did,
			issuerConfig: config,
			format: "ldp_vc",
			output: "individual",
			records,
		});

		const vc = result.credentials[0];
		expect(vc).toBeDefined();
		if (!vc) return;

		// Tamper: change the resource field after signing
		const tampered = {
			...vc,
			credentialSubject: {
				...vc.credentialSubject,
				target: "mcp:tool:TAMPERED",
			},
		};

		const verified = await verifier.verifyCredential(tampered, config.publicKeyJwk);
		expect(verified.success).toBe(false);
	});
});

describe("exportAuditAsVC – filter test", () => {
	it("returns only deny records when filter is applied", async () => {
		const { config, did } = await makeConfig();
		const records = makeRecords();

		const result = await exportAuditAsVC({
			since: T0,
			until: T2,
			issuerDid: did,
			issuerConfig: config,
			format: "ldp_vc",
			output: "individual",
			records,
			// Records 10–19 are "denied" or "rate_limited" (non-allowed)
			filter: (r) => r.result === "denied",
		});

		// Records 10–14 are "denied" (5 records)
		expect(result.count).toBe(5);
		for (const vc of result.credentials) {
			const subject = vc.credentialSubject as { decision?: string };
			expect(subject.decision).toBe("deny");
		}
	});
});

describe("exportAuditAsVC – empty range test", () => {
	it("returns empty result when no records fall in the range", async () => {
		const { config, did } = await makeConfig();
		const records = makeRecords();

		const farFuture = new Date("2099-01-01T00:00:00Z");
		const farFuture2 = new Date("2099-12-31T00:00:00Z");

		const result = await exportAuditAsVC({
			since: farFuture,
			until: farFuture2,
			issuerDid: did,
			issuerConfig: config,
			format: "ldp_vc",
			output: "individual",
			records,
		});

		expect(result.credentials).toHaveLength(0);
		expect(result.count).toBe(0);
		expect(result.presentation).toBeUndefined();
	});
});
