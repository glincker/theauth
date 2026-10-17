import type { createDelegationModule } from "../delegation/delegation.js";
import type { TheAuthHooks } from "../hooks/lifecycle.js";
import type { HookRuntime } from "../hooks/runtime.js";
import type { DelegateInput, DelegationChain } from "../types.js";
import type { createAgentModule } from "./agent.js";

type AgentModule = ReturnType<typeof createAgentModule>;
type DelegationModule = ReturnType<typeof createDelegationModule>;

type VaultRevoker = { revokeForDelegation?: (id: string) => Promise<number> };

/** The token vault is an optional plugin; consents tied to a revoked chain die with it. */
function vaultOf(pluginContext: Record<string, unknown>): VaultRevoker | undefined {
	return pluginContext.tokenVault as VaultRevoker | undefined;
}

export interface AgentFacadeDeps {
	agentModule: AgentModule;
	delegationModule: DelegationModule;
	hooks: TheAuthHooks;
	guardAgentCreate: HookRuntime["guardAgentCreate"];
	pluginContext: Record<string, unknown>;
}

/** Agent, delegate and delegation facades that add hooks and vault cleanup around the raw modules. */
export function createAgentFacade(deps: AgentFacadeDeps) {
	const { agentModule, delegationModule, hooks, guardAgentCreate, pluginContext } = deps;

	const agent = {
		async create(...args: Parameters<AgentModule["create"]>): ReturnType<AgentModule["create"]> {
			const [input] = args;

			await guardAgentCreate(input);

			const created = await agentModule.create(input);

			void hooks.afterAgentCreate?.(created);

			return created;
		},

		async revoke(agentId: string): ReturnType<AgentModule["revoke"]> {
			const result = await agentModule.revoke(agentId);
			// Vault consents tied to the cascaded chains die with them.
			const vault = vaultOf(pluginContext);
			for (const chainId of result.revokedDelegations) {
				await vault?.revokeForDelegation?.(chainId);
			}
			void hooks.onAgentRevoke?.(agentId);
			return result;
		},

		async rotate(...args: Parameters<AgentModule["rotate"]>): ReturnType<AgentModule["rotate"]> {
			return agentModule.rotate(...args);
		},

		get: agentModule.get,
		list: agentModule.list,
		update: agentModule.update,
		validateToken: agentModule.validateToken,
	};

	async function delegate(input: DelegateInput): Promise<DelegationChain> {
		const parentAgent = await agentModule.get(input.fromAgent);
		if (!parentAgent) throw new Error(`Parent agent "${input.fromAgent}" not found`);
		if (parentAgent.status !== "active") {
			throw new Error(`Parent agent "${parentAgent.name}" is ${parentAgent.status}`);
		}
		return delegationModule.delegate(input);
	}

	const delegation = {
		/** Revokes a chain and its descendants. Pass `revokedBy` to record who did it in the audit rows. */
		revoke: async (chainId: string, opts?: { revokedBy?: string }): Promise<void> => {
			await delegationModule.revokeDelegation(
				chainId,
				opts?.revokedBy ? { revokedBy: opts.revokedBy } : {},
			);
			// Vault consents tied to this chain die with it (reads also re-check the chain).
			await vaultOf(pluginContext)?.revokeForDelegation?.(chainId);
		},
		getEffectivePermissions: delegationModule.getEffectivePermissions,
		listChains: delegationModule.listChains,
	};

	return { agent, delegate, delegation };
}
