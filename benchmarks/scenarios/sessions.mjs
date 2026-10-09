import { measure } from "../lib/stats.mjs";

export const name = "sessions";

export async function run(fx, profile, record) {
	const theauth = await fx.open({ session: true, auditAll: false });
	const manager = theauth.auth.session;
	if (!manager) throw new Error("session manager missing");
	const userId = await fx.seedUser(theauth);
	const base = { backend: fx.backendName };

	record({
		...base,
		scenario: "session",
		variant: "create",
		...(await measure(() => manager.create(userId, { ua: "bench" }), {
			iterations: profile.db,
			warmup: profile.warmup,
		})),
	});

	const { token } = await manager.create(userId);
	record({
		...base,
		scenario: "session",
		variant: "validate (JWT verify + DB row lookup)",
		...(await measure(
			async () => {
				if (!(await manager.validate(token))) throw new Error("validate returned null");
			},
			{ iterations: profile.db, warmup: profile.warmup },
		)),
	});
}
