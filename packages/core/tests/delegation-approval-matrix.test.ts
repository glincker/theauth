/** A grant covering several actions never drops the parent's requireApproval for a covered action. */
import { describe, expect, it } from "vitest";
import { future, makeTheAuth, newAgent } from "./hook-test-utils.js";

const PARENT = [
	{ resource: "db:prod", actions: ["write"], constraints: { requireApproval: true } },
	{ resource: "db:*", actions: ["read", "write"] },
];

async function child(requested: { resource: string; actions: string[] }[]) {
	const theauth = await makeTheAuth({});
	const parent = await newAgent(theauth, "p", PARENT);
	const kid = await newAgent(theauth, "c", []);
	const chain = await theauth.delegate({
		fromAgent: parent.id,
		toAgent: kid.id,
		permissions: requested,
		expiresAt: future(),
	});
	return { theauth, parent, kid, chain };
}

describe("delegation keeps the parent's approval requirement per action", () => {
	it("parent itself needs approval for write on db:prod", async () => {
		const theauth = await makeTheAuth({});
		const parent = await newAgent(theauth, "p", PARENT);
		expect(
			(await theauth.authorize(parent.id, { action: "write", resource: "db:prod" })).allowed,
		).toBe(false);
		expect(
			(await theauth.authorize(parent.id, { action: "read", resource: "db:prod" })).allowed,
		).toBe(true);
	});

	it("multi-action grant: write still needs approval, read does not", async () => {
		const { theauth, kid } = await child([{ resource: "db:prod", actions: ["read", "write"] }]);
		expect(
			(await theauth.authorize(kid.id, { action: "write", resource: "db:prod" })).allowed,
		).toBe(false);
		expect((await theauth.authorize(kid.id, { action: "read", resource: "db:prod" })).allowed).toBe(
			true,
		);
	});

	it("action order in the request does not matter", async () => {
		const { theauth, kid } = await child([{ resource: "db:prod", actions: ["write", "read"] }]);
		expect(
			(await theauth.authorize(kid.id, { action: "write", resource: "db:prod" })).allowed,
		).toBe(false);
		expect((await theauth.authorize(kid.id, { action: "read", resource: "db:prod" })).allowed).toBe(
			true,
		);
	});

	it("a broader child resource inherits the gate on every action the gating rule covers", async () => {
		const { theauth, kid } = await child([{ resource: "db:*", actions: ["read", "write"] }]);
		expect(
			(await theauth.authorize(kid.id, { action: "write", resource: "db:prod" })).allowed,
		).toBe(false);
		expect((await theauth.authorize(kid.id, { action: "read", resource: "db:prod" })).allowed).toBe(
			true,
		);
	});

	it("an ungated resource stays ungated", async () => {
		const { theauth, kid } = await child([{ resource: "db:staging", actions: ["read", "write"] }]);
		expect(
			(await theauth.authorize(kid.id, { action: "write", resource: "db:staging" })).allowed,
		).toBe(true);
	});

	it("the stored grant carries requireApproval only on the gated action", async () => {
		const { chain } = await child([{ resource: "db:prod", actions: ["read", "write"] }]);
		const gated = chain.permissions.filter((p) => p.constraints?.requireApproval);
		expect(gated.map((p) => p.actions)).toEqual([["write"]]);
		const open = chain.permissions.filter((p) => !p.constraints?.requireApproval);
		expect(open.flatMap((p) => p.actions)).toEqual(["read"]);
	});

	it("a wildcard parent action still carries the gate", async () => {
		const theauth = await makeTheAuth({});
		const parent = await newAgent(theauth, "p", [
			{ resource: "db:prod", actions: ["*"], constraints: { requireApproval: true } },
		]);
		const kid = await newAgent(theauth, "c", []);
		await theauth.delegate({
			fromAgent: parent.id,
			toAgent: kid.id,
			permissions: [{ resource: "db:prod", actions: ["read", "write"] }],
			expiresAt: future(),
		});
		for (const action of ["read", "write"]) {
			expect((await theauth.authorize(kid.id, { action, resource: "db:prod" })).allowed).toBe(
				false,
			);
		}
	});
});
