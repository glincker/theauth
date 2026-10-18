import { eq } from "drizzle-orm";
import { auditLogs, delegationChains } from "../src/db/schema.js";
import type { TheAuthHooks } from "../src/hooks/lifecycle.js";
import type { HookSafetyConfig } from "../src/hooks/safety.js";
import type { TheAuth } from "../src/theauth.js";
import { createTheAuth } from "../src/theauth.js";
import type { Permission, TheAuthConfig } from "../src/types.js";

export async function makeTheAuth(options: {
	hooks?: TheAuthHooks;
	hookSafety?: HookSafetyConfig;
	auditAll?: boolean;
	tamperEvident?: boolean;
	policy?: TheAuthConfig["policy"];
}): Promise<TheAuth> {
	const theauth = await createTheAuth({
		database: { provider: "sqlite", url: ":memory:" },
		agents: {
			enabled: true,
			maxPerUser: 20,
			defaultPermissions: [],
			auditAll: options.auditAll ?? true,
			tokenExpiry: "24h",
		},
		hooks: options.hooks,
		hookSafety: options.hookSafety,
		audit: options.tamperEvident ? { tamperEvident: true, hmacKey: "test-key" } : undefined,
		policy: options.policy,
	});
	for (const id of ["user-1", "user-2"]) {
		await theauth.user.create({ id, email: `${id}@example.com` });
	}
	return theauth;
}

export const READ_GITHUB: Permission[] = [{ resource: "mcp:github:*", actions: ["read", "write"] }];

export function newAgent(
	theauth: TheAuth,
	name: string,
	permissions: Permission[],
	ownerId = "user-1",
) {
	return theauth.agent.create({ ownerId, name, type: "autonomous", permissions });
}

export const future = () => new Date(Date.now() + 60 * 60 * 1000);

export const pause = (ms = 5) => new Promise((resolve) => setTimeout(resolve, ms));

export async function delegateTo(
	theauth: TheAuth,
	fromAgent: string,
	toAgent: string,
	permissions: Permission[] = READ_GITHUB,
) {
	const chain = await theauth.delegate({ fromAgent, toAgent, permissions, expiresAt: future() });
	await pause();
	return chain;
}

export async function expireChain(theauth: TheAuth, chainId: string) {
	await theauth.db
		.update(delegationChains)
		.set({ expiresAt: new Date(Date.now() - 1000) })
		.where(eq(delegationChains.id, chainId));
}

export async function auditRows(theauth: TheAuth, agentId: string) {
	return theauth.db.select().from(auditLogs).where(eq(auditLogs.agentId, agentId));
}
