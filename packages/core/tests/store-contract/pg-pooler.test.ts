import { runStoreContract } from "../../../test-utils/src/store-contract/index.js";
import { bootTarget } from "./boot.js";

/**
 * Postgres behind a transaction mode pooler (Supabase Supavisor on port 6543, Neon `-pooler`
 * hosts, PgBouncer). Set THEAUTH_TEST_PG_POOLER_URL to a pooler URL for an existing, empty
 * database. Prepared statements are off on that pooler (PgBouncer `max_prepared_statements = 0`),
 * as on Supabase's transaction pooler, so this fails if theAuth ever relies on a server side
 * prepared statement or session state.
 *
 * Ten parallel callers, not 24: the hourly budget reserves before it checks, so a burst larger than the
 * budget can refuse a call that would have fit when a pooler interleaves the bumps (documented on
 * `rateLimits.reserve`, it never admits past the limit). The race tests still use ten contenders per row.
 */
const poolerUrl = process.env.THEAUTH_TEST_PG_POOLER_URL;

if (poolerUrl) {
	runStoreContract(
		"postgres via transaction pooler",
		() => bootTarget(() => ({ provider: "postgres", url: poolerUrl }), true),
		{ parallel: 10 },
	);
} else {
	runStoreContract(
		"postgres via transaction pooler",
		() => Promise.reject(new Error("unreachable")),
		{
			skip: true,
		},
	);
}
