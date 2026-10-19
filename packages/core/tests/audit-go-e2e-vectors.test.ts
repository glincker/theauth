/**
 * End to end: chains written by the real Go code (BuildChainEntryWith, stable and rotating `r1:`
 * pseudonyms, one erased row), a head checkpoint signed by the real Go CreateHeadCheckpoint, and the
 * Go verdicts for four cuts of the log. The TypeScript chain verifier and head verifier must accept
 * and reject the same rows. Generator: scripts/go-e2e-vectors.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import type { CheckpointPublicKey } from "../src/audit/checkpoint-types.js";
import type { GoAuditRow } from "../src/audit/go-chain-verify.js";
import { goRotatedPeriod, verifyGoAuditChain } from "../src/audit/go-chain-verify.js";
import type { GoHeadCheckpoint } from "../src/audit/go-head-verify.js";
import { verifyGoHeadCheckpoint } from "../src/audit/go-head-verify.js";

interface Fixture {
	pseudonymSecretHex: string;
	periodSecretsHex: Record<string, string>;
	shreddedPeriod: string;
	keys: CheckpointPublicKey[];
	head: GoHeadCheckpoint;
	chains: { chainKey: string; rows: GoAuditRow[] }[];
	cuts: {
		name: string;
		keep: Record<string, number>;
		expected: { valid: boolean; reason?: string; chainKey?: string };
	}[];
}

const fx = JSON.parse(
	readFileSync(
		fileURLToPath(new URL("./fixtures/go-e2e-head-vectors.json", import.meta.url)),
		"utf8",
	),
) as Fixture;

const allRows = (): GoAuditRow[] => fx.chains.flatMap((c) => structuredClone(c.rows));
const live = (): Record<string, string> => {
	const { [fx.shreddedPeriod]: _gone, ...rest } = fx.periodSecretsHex;
	return rest;
};
const rotatedRows = (): number =>
	allRows().filter((r) =>
		[r.actorUserPseudonym, r.subjectPseudonym, r.actorPseudonym, r.approverPseudonym].some(
			(p) => typeof p === "string" && goRotatedPeriod(p) !== null,
		),
	).length;

describe("Go rotating pseudonym tags", () => {
	it("parses the tag like Go PseudonymPeriod", () => {
		expect(goRotatedPeriod("r1:20000:1eca")).toBe(20000n);
		expect(goRotatedPeriod("r1:-5:abcd")).toBe(-5n);
		expect(goRotatedPeriod("r1:abc:ff")).toBeNull();
		expect(goRotatedPeriod("r1:12")).toBeNull();
		expect(goRotatedPeriod("ab".repeat(32))).toBeNull();
		expect(goRotatedPeriod("r1:9223372036854775808:ff")).toBeNull();
	});
});

describe("verifyGoAuditChain over Go chains with rotating pseudonyms", () => {
	it("the fixture holds rotated and stable rows", () => {
		expect(rotatedRows()).toBeGreaterThanOrEqual(4);
		expect(allRows().length).toBe(11);
	});

	it("accepts them with the stable secret only (rotated pseudonyms are not compared under it)", async () => {
		const r = await verifyGoAuditChain(allRows(), { pseudonymSecret: fx.pseudonymSecretHex });
		expect(r.firstFailure).toBeUndefined();
		expect(r.ok).toBe(true);
		expect(r.checked).toBe(11);
		expect(r.erased).toBe(1);
		expect(r.pseudonymsUnchecked).toBeGreaterThan(0);
	});

	it("accepts them with no secret at all and counts the rows it trusted", async () => {
		const r = await verifyGoAuditChain(allRows());
		expect(r.ok).toBe(true);
		expect(r.pseudonymsUnchecked).toBeGreaterThan(0);
	});

	it("checks every rotated pseudonym when all period secrets are given", async () => {
		const r = await verifyGoAuditChain(allRows(), {
			pseudonymSecret: fx.pseudonymSecretHex,
			periodSecrets: fx.periodSecretsHex,
		});
		expect(r.ok).toBe(true);
		expect(r.pseudonymsUnchecked).toBe(0);
	});

	it("skips only the shredded period, as Go does", async () => {
		const r = await verifyGoAuditChain(allRows(), {
			pseudonymSecret: fx.pseudonymSecretHex,
			periodSecrets: new Map(Object.entries(live())),
		});
		expect(r.ok).toBe(true);
		expect(r.pseudonymsUnchecked).toBe(1);
	});

	it("catches an edited raw id on a rotated row once its period secret is known", async () => {
		const rows = allRows();
		const target = rows.find(
			(r) => r.chainSeq === 4 && r.organizationId === fx.chains[0]?.chainKey,
		);
		expect(target?.actorId).toBe("agent_b");
		(target as GoAuditRow).actorId = "agent_evil";
		const opts = { pseudonymSecret: fx.pseudonymSecretHex };
		const blind = await verifyGoAuditChain(structuredClone(rows), opts);
		expect(blind.ok).toBe(true);
		const r = await verifyGoAuditChain(rows, { ...opts, periodSecrets: live() });
		expect(r.ok).toBe(false);
		expect(r.firstFailure?.reason).toBe("pseudonym_mismatch");
		expect(r.firstFailure?.detail).toBe("actorId");
	});

	it("an edited raw id in a shredded period cannot be caught (documented Go limit)", async () => {
		const rows = allRows();
		const target = rows.find(
			(r) => r.chainSeq === 2 && r.organizationId === fx.chains[0]?.chainKey,
		);
		(target as GoAuditRow).subjectId = "user_evil";
		const r = await verifyGoAuditChain(rows, { periodSecrets: live() });
		expect(r.ok).toBe(true);
	});

	it("rejects a wrong period secret", async () => {
		const bad = { ...fx.periodSecretsHex, [Object.keys(live())[0] as string]: "00".repeat(32) };
		const r = await verifyGoAuditChain(allRows(), { periodSecrets: bad });
		expect(r.firstFailure?.reason).toBe("pseudonym_mismatch");
	});

	it("rejects a malformed period key", async () => {
		await expect(verifyGoAuditChain(allRows(), { periodSecrets: { abc: "00" } })).rejects.toThrow(
			/period number/,
		);
	});
});

describe("Go signed head over the same chains", () => {
	const subset = (keep: Record<string, number>): GoAuditRow[] =>
		allRows().filter((r) => {
			const k = keep[r.organizationId ?? ""];
			return k !== undefined && (r.chainSeq ?? 0) <= k;
		});

	for (const c of fx.cuts) {
		it(`${c.name} gets the verdict Go gave`, async () => {
			const rows = subset(c.keep);
			const r = await verifyGoHeadCheckpoint(fx.head, fx.keys, rows);
			expect(r.valid).toBe(c.expected.valid);
			if (!r.valid) {
				expect(r.reason).toBe(c.expected.reason);
				expect(r.chainKey ?? "").toBe(c.expected.chainKey ?? "");
			}
		});
	}

	it("the log the head accepts also passes the chain verifier, a cut log passes it too", async () => {
		const full = subset(fx.cuts[0]?.keep ?? {});
		const opts = { periodSecrets: live(), pseudonymSecret: fx.pseudonymSecretHex };
		expect((await verifyGoAuditChain(full, opts)).ok).toBe(true);
		expect((await verifyGoHeadCheckpoint(fx.head, fx.keys, full)).valid).toBe(true);
		const cut = subset(fx.cuts[1]?.keep ?? {});
		// The chain alone cannot see the cut, only the signed head can.
		expect((await verifyGoAuditChain(cut, opts)).ok).toBe(true);
		const head = await verifyGoHeadCheckpoint(fx.head, fx.keys, cut);
		expect(head.valid).toBe(false);
	});
});
