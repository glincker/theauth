import { measure } from "../lib/stats.mjs";

export const name = "audit";

function rowFor(fx, agent, i) {
	return {
		id: fx.uid("audit"),
		agentId: agent.id,
		userId: agent.ownerId,
		action: "read",
		resource: `tool:bench:${i}`,
		parameters: { n: i },
		result: "allowed",
		reason: null,
		durationMs: 1,
		timestamp: new Date(),
	};
}

async function agents(theauth, ownerId, count) {
	const out = [];
	for (let i = 0; i < count; i++) {
		out.push(
			await theauth.agent.create({
				ownerId,
				name: `audit-${i}`,
				type: "autonomous",
				permissions: [],
			}),
		);
	}
	return out;
}

export async function run(fx, profile, record) {
	const base = { backend: fx.backendName };
	const iterations = profile.audit;
	const warmup = profile.warmup;

	// Chain off: a plain insert.
	{
		const theauth = await fx.open({ auditAll: false });
		const [agent] = await agents(theauth, await fx.seedUser(theauth), 1);
		record({
			...base,
			scenario: "audit append",
			variant: "tamperEvident off",
			...(await measure((i) => fx.core.insertAuditRow(theauth.db, rowFor(fx, agent, i)), {
				iterations,
				warmup,
			})),
		});
	}

	// Chain on, one writer, then N writers on the same agent and on separate agents.
	for (const writers of profile.contention) {
		const theauth = await fx.open({ auditAll: false, tamperEvident: true });
		const owner = await fx.seedUser(theauth);
		const pool = await agents(theauth, owner, writers);
		const label = writers === 1 ? "1 writer" : `${writers} writers`;

		record({
			...base,
			scenario: "audit append",
			variant: `tamperEvident on, ${label}, same agent`,
			...(await measure((i) => fx.core.insertAuditRow(theauth.db, rowFor(fx, pool[0], i)), {
				iterations,
				warmup,
				concurrency: writers,
			})),
		});

		if (writers > 1) {
			record({
				...base,
				scenario: "audit append",
				variant: `tamperEvident on, ${label}, separate agents`,
				...(await measure(
					(i) => fx.core.insertAuditRow(theauth.db, rowFor(fx, pool[Math.abs(i) % writers], i)),
					{ iterations, warmup, concurrency: writers },
				)),
			});
		}
	}

	// Several independent instances on one database. Each has its own in-process
	// queue, so same-agent writers really race and the unique index retry path runs.
	if (fx.backend.multiInstance) {
		for (const writers of profile.instances) {
			const instances = [];
			for (let i = 0; i < writers; i++)
				instances.push(await fx.open({ auditAll: false, tamperEvident: true }));
			const owner = await fx.seedUser(instances[0]);
			const [agent] = await agents(instances[0], owner, 1);
			record({
				...base,
				scenario: "audit append",
				variant: `tamperEvident on, ${writers} instances, same agent (index retry path)`,
				...(await measure(
					(i) => fx.core.insertAuditRow(instances[Math.abs(i) % writers].db, rowFor(fx, agent, i)),
					{
						iterations: Math.min(iterations, profile.instanceIterations),
						warmup: 0,
						concurrency: writers,
					},
				)),
			});
		}
	}
}
