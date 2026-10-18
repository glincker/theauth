import type { TheAuth } from "../theauth.js";
import { createTheAuth } from "../theauth.js";
import type { AgentIdentity, Permission, TheAuthConfig } from "../types.js";

export interface SeedAgentInput {
	/** User id owning the agent. Defaults to a shared seeded user. */
	owner?: string;
	name?: string;
	permissions: Permission[];
	type?: AgentIdentity["type"];
}

export interface TestAuth extends TheAuth {
	seedUser(email?: string): Promise<{ id: string; email: string }>;
	seedAgent(input: SeedAgentInput): Promise<AgentIdentity>;
}

const DEFAULT_OWNER_EMAIL = "owner@theauth.test";

/** In-memory TheAuth (sqlite `:memory:`) with seeding helpers. Hooks and other config pass through. */
export async function createTestAuth(config: Partial<TheAuthConfig> = {}): Promise<TestAuth> {
	const auth = await createTheAuth({
		...config,
		database: config.database ?? { provider: "sqlite", url: ":memory:" },
		agents: config.agents ?? {
			enabled: true,
			maxPerUser: 1000,
			defaultPermissions: [],
			auditAll: false,
			tokenExpiry: "1h",
		},
	});
	let counter = 0;
	const owners = new Map<string, { id: string; email: string }>();

	async function seedUser(email?: string): Promise<{ id: string; email: string }> {
		const address = email ?? `user-${++counter}@theauth.test`;
		const known = owners.get(address);
		if (known) return known;
		const row = await auth.user.create({ email: address });
		const user = { id: row.id, email: address };
		owners.set(address, user);
		return user;
	}

	async function seedAgent(input: SeedAgentInput): Promise<AgentIdentity> {
		const owner = input.owner ?? (await seedUser(DEFAULT_OWNER_EMAIL)).id;
		const { token: _token, ...agent } = await auth.agent.create({
			ownerId: owner,
			name: input.name ?? `test-agent-${++counter}`,
			type: input.type ?? "autonomous",
			permissions: input.permissions,
		});
		return agent as AgentIdentity;
	}

	return Object.assign(auth, { seedUser, seedAgent });
}
