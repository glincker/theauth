import { describe } from "vitest";
import { defineApprovalRaces } from "./approval-races.js";
import { defineAuditOrder } from "./audit-order.js";
import { defineClaimRaces } from "./claim-races.js";
import type { StoreContractOptions, StoreContractTarget } from "./types.js";
import { defineUniqueConflict } from "./unique-conflict.js";

export type {
	ContractAdminDecisions,
	ContractAuth,
	ContractMailbox,
	ContractTokenFamilies,
	ContractUser,
	StoreContractOptions,
	StoreContractTarget,
} from "./types.js";

/**
 * Runs the store contract against one backend: claim races, unique conflicts and audit chain order.
 * `make` boots a fresh TheAuth instance on the backend each time it is called. Call it from a vitest file:
 *
 * ```ts
 * runStoreContract("postgres", () => bootOn(pgUrl), { skip: !pgUrl });
 * ```
 *
 * The suite only talks to the public instance surface, so it pins today's behavior whichever store sits underneath.
 */
export function runStoreContract(
	name: string,
	make: () => Promise<StoreContractTarget>,
	options: StoreContractOptions = {},
): void {
	const parallel = options.parallel ?? 24;
	const timeout = options.timeoutMs ?? 120_000;
	const run = options.skip ? describe.skip : describe;
	run(`store contract: ${name}`, { timeout }, () => {
		defineClaimRaces(make, parallel);
		defineApprovalRaces(make, parallel);
		defineUniqueConflict(make, parallel);
		defineAuditOrder(make, parallel);
	});
}
