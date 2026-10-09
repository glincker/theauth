import { measure } from "../lib/stats.mjs";

const READ_ALL = [{ resource: "tool:*", actions: ["read"] }];

export const name = "agents-tokens";

export async function run(fx, profile, record) {
	const theauth = await fx.open({ auditAll: false, session: true });
	const ownerId = await fx.seedUser(theauth);
	const base = { backend: fx.backendName };

	// createAgent for one owner. create() reads every active agent the owner
	// already has to enforce maxPerUser, so latency can grow with the count.
	record({
		...base,
		scenario: "createAgent",
		variant: "single owner (growing agent count)",
		...(await measure(
			(i) =>
				theauth.agent.create({
					ownerId,
					name: `a-${i}`,
					type: "autonomous",
					permissions: READ_ALL,
				}),
			{ iterations: profile.db, warmup: profile.warmup },
		)),
	});

	// createAgent with a fresh owner each time, so the maxPerUser read stays tiny.
	const owners = [];
	for (let i = 0; i < profile.db + profile.warmup; i++) owners.push(await fx.seedUser(theauth));
	record({
		...base,
		scenario: "createAgent",
		variant: "fresh owner each call",
		...(await measure(
			(i) =>
				theauth.agent.create({
					ownerId: owners[i < 0 ? profile.db - i - 1 : i],
					name: `b-${i}`,
					type: "autonomous",
					permissions: READ_ALL,
				}),
			{ iterations: profile.db, warmup: profile.warmup },
		)),
	});

	const agent = await theauth.agent.create({
		ownerId,
		name: "token-subject",
		type: "autonomous",
		permissions: READ_ALL,
	});

	record({
		...base,
		scenario: "token issue",
		variant: "agent.rotate (opaque token, hash stored)",
		...(await measure(() => theauth.agent.rotate(agent.id), {
			iterations: profile.db,
			warmup: profile.warmup,
		})),
	});

	const fresh = await theauth.agent.rotate(agent.id);
	record({
		...base,
		scenario: "token verify",
		variant: "agent.validateToken (DB lookup + last_active write)",
		...(await measure(() => theauth.agent.validateToken(fresh.token), {
			iterations: profile.db,
			warmup: profile.warmup,
		})),
	});

	const jwt = fx.core.createJwtSessionModule(
		{ secret: "bench-jwt-secret-0123456789abcdef0123", accessTokenTtl: 900 },
		theauth.db,
	);
	const issued = await jwt.createSession({ id: ownerId, email: `${ownerId}@bench.invalid` });
	if (!issued.success) throw new Error(`jwt createSession failed: ${issued.error.message}`);
	record({
		...base,
		scenario: "token issue",
		variant: "jwt createSession (access JWT + refresh row insert)",
		...(await measure(() => jwt.createSession({ id: ownerId, email: `${ownerId}@bench.invalid` }), {
			iterations: profile.db,
			warmup: profile.warmup,
		})),
	});
	record({
		...base,
		scenario: "token verify",
		variant: "jwt verifySession (stateless, no DB)",
		...(await measure(() => jwt.verifySession(issued.data.accessToken), {
			iterations: profile.fast,
			warmup: profile.warmup,
		})),
	});
}
