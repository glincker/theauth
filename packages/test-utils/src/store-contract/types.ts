/**
 * The slice of a TheAuth instance the store contract drives. It is structural on purpose: the real
 * `TheAuth` type satisfies it, and a test target never needs to import core.
 */

export interface ContractUser {
	id: string;
	email: string;
}

export interface ContractAuth {
	user: {
		create(input: { email: string }): Promise<ContractUser>;
	};
	agent: {
		create(input: {
			ownerId: string;
			name: string;
			type: "autonomous";
			permissions: Array<{
				resource: string;
				actions: string[];
				constraints?: { requireApproval?: boolean };
			}>;
		}): Promise<{ id: string }>;
	};
	magicLink?: {
		sendLink(email: string): Promise<unknown>;
		verify(token: string): Promise<unknown | null>;
	};
	emailOtp?: {
		sendCode(email: string): Promise<unknown>;
		verifyCode(email: string, code: string): Promise<unknown | null>;
	};
	approval: {
		request(input: {
			agentId: string;
			userId: string;
			action: string;
			resource: string;
		}): Promise<{ id: string }>;
		approve(id: string, decidedBy: string): Promise<unknown>;
		deny(id: string, decidedBy: string): Promise<unknown>;
		get(id: string): Promise<{ status: string } | null>;
	};
	authorize(
		agentId: string,
		request: { action: string; resource: string; approvalId?: string },
	): Promise<{ allowed: boolean }>;
	audit: {
		query(filter: { agentId: string; limit?: number }): Promise<unknown[]>;
		verifyAuditChain(opts?: { agentId?: string }): Promise<
			| {
					success: true;
					data: {
						ok: boolean;
						checked: number;
						unchained: number;
						heads: Array<{ agentId: string; seq: number }>;
					};
			  }
			| { success: false; error: { code: string; message: string } }
		>;
	};
}

/** Messages the email modules would have delivered, filled by the target's send callbacks. */
export interface ContractMailbox {
	magicTokens: string[];
	otpCodes: string[];
}

/** A refresh token family store, for the rotation claim. Optional because it is not on the public surface. */
export interface ContractTokenFamilies {
	rotateOnce(userId: string, parallel: number): Promise<{ ok: number; others: string[] }>;
}

/** What an adapter must hand the suite. */
export interface StoreContractTarget {
	auth: ContractAuth;
	mail: ContractMailbox;
	/**
	 * A second instance on the same database, standing for a second process: its own driver handle, so in-process write queues do not serialize it with this one. Leave it out when the backend cannot be shared (an in-memory database).
	 */
	peer?: () => Promise<StoreContractTarget>;
	/**
	 * Inserts the same unique key twice with the backend's own driver and reports what the second insert threw: "typed" when it is a StoreConflictError (or maps to one), "untyped" for any other error, "none" when the database accepted a duplicate.
	 */
	duplicateInsert?: () => Promise<"typed" | "untyped" | "none">;
	tokenFamilies?: ContractTokenFamilies;
	close(): Promise<void>;
}

export interface StoreContractOptions {
	/** Parallel callers per claim. Default 24, matching the Go suite. */
	parallel?: number;
	/** Skip the whole suite, for a backend that is not configured. */
	skip?: boolean;
	/** Per-test timeout in milliseconds. Default 120000. */
	timeoutMs?: number;
}
