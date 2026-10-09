import { measure } from "../lib/stats.mjs";

const PERMS = [{ resource: "tool:*", actions: ["read"] }];
const FAR_FUTURE = new Date(Date.now() + 365 * 24 * 3600 * 1000);

export const name = "authorize";

/** Build agents[0..depth]; agents[0] owns the permission, each next one receives it by delegation. */
async function buildChain(theauth, ownerId, depth) {
	const agents = [];
	for (let i = 0; i <= depth; i++) {
		agents.push(
			await theauth.agent.create({
				ownerId,
				name: `chain-${depth}-${i}`,
				type: "delegated",
				permissions: i === 0 ? PERMS : [],
			}),
		);
	}
	for (let i = 0; i < depth; i++) {
		await theauth.delegate({
			fromAgent: agents[i].id,
			toAgent: agents[i + 1].id,
			permissions: PERMS,
			expiresAt: FAR_FUTURE,
			maxDepth: 3,
		});
	}
	return agents[depth];
}

export async function run(fx, profile, record) {
	const base = { backend: fx.backendName };
	const opts = { iterations: profile.db, warmup: profile.warmup };

	// Rate limit stored in the database (maxCallsPerHour constraint): one read,
	// then one update or insert, on every allowed call.
	{
		const theauth = await fx.open({ auditAll: false });
		const ownerId = await fx.seedUser(theauth);
		const limited = await theauth.agent.create({
			ownerId,
			name: "rate-limited",
			type: "autonomous",
			permissions: [
				{ resource: "tool:*", actions: ["read"], constraints: { maxCallsPerHour: 1_000_000_000 } },
			],
		});
		record({
			...base,
			scenario: "rate-limit check",
			variant: "authorize with maxCallsPerHour constraint (DB counter), audit off",
			...(await measure(
				() => theauth.authorize(limited.id, { action: "read", resource: "tool:search" }),
				opts,
			)),
		});
	}
	const allow = { action: "read", resource: "tool:search" };
	const deny = { action: "write", resource: "tool:search" };

	for (const auditAll of [false, true]) {
		const theauth = await fx.open({ auditAll });
		const ownerId = await fx.seedUser(theauth);
		const audit = auditAll ? "audit row per call" : "audit off";
		const simulator = fx.core.createSimulator({ db: theauth.db });

		for (const depth of [0, 1, 2, 3]) {
			const subject =
				depth === 0
					? await theauth.agent.create({
							ownerId,
							name: "direct",
							type: "autonomous",
							permissions: PERMS,
						})
					: await buildChain(theauth, ownerId, depth);
			const how = depth === 0 ? "direct permission" : `delegation depth ${depth}`;

			for (const [label, req] of [
				["allow", allow],
				["deny", deny],
			]) {
				record({
					...base,
					scenario: "authorize",
					variant: `${label}, ${how}, ${audit}`,
					...(await measure(() => theauth.authorize(subject.id, req), opts)),
				});
			}

			// simulate() never writes, so it only needs one pass per depth.
			if (!auditAll) {
				for (const [label, req] of [
					["allow", allow],
					["deny", deny],
				]) {
					record({
						...base,
						scenario: "simulate",
						variant: `${label}, ${how}`,
						...(await measure(async () => {
							const r = await simulator.simulate({ agentId: subject.id, ...req });
							if (!r.success) throw new Error(r.error.message);
						}, opts)),
					});
				}
			}
		}
	}
}
