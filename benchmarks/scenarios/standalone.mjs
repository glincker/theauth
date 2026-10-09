import { measure } from "../lib/stats.mjs";

export const name = "standalone";

/** Scenarios with no database: in-process rate limiting and password hashing. */
export async function run(core, profile, record) {
	const base = { backend: "none (in process)" };

	const limiter = core.createRateLimiter({ max: 1_000_000_000, window: 60 });
	record({
		...base,
		scenario: "rate-limit check",
		variant: "createRateLimiter.check, 1 key (sliding window array)",
		...(await measure(() => limiter.check("one-key"), {
			iterations: profile.fast,
			warmup: profile.warmup,
		})),
	});
	record({
		...base,
		scenario: "rate-limit check",
		variant: "createRateLimiter.check, rotating 1000 keys",
		...(await measure((i) => limiter.check(`key-${Math.abs(i) % 1000}`), {
			iterations: profile.fast,
			warmup: profile.warmup,
		})),
	});

	const store = new core.MemoryStore();
	record({
		...base,
		scenario: "rate-limit check",
		variant: "MemoryStore.increment (fixed window counter)",
		...(await measure((i) => store.increment(`key-${Math.abs(i) % 1000}`, 60_000), {
			iterations: profile.fast,
			warmup: profile.warmup,
		})),
	});

	record({
		...base,
		scenario: "password hash",
		variant: "pbkdf2Hash (default cost)",
		...(await measure(() => core.pbkdf2Hash("correct horse battery staple"), {
			iterations: profile.slow,
			warmup: Math.min(profile.warmup, 3),
		})),
	});
	const stored = await core.pbkdf2Hash("correct horse battery staple");
	record({
		...base,
		scenario: "password hash",
		variant: "pbkdf2Verify (default cost)",
		...(await measure(() => core.pbkdf2Verify("correct horse battery staple", stored), {
			iterations: profile.slow,
			warmup: Math.min(profile.warmup, 3),
		})),
	});
}
