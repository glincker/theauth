import type { GoDelegation, GrantDelegationInput } from "@glinr/theauth-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { unwrap, useTheAuthGoClient } from "./client-context.js";
import { authKeys } from "./keys.js";
import type { RevokeAgentInput } from "./use-agents.js";

/** The signed-in user's delegation grants to agents. */
export function useDelegations() {
	const client = useTheAuthGoClient();
	const qc = useQueryClient();
	const refresh = () => qc.invalidateQueries({ queryKey: authKeys.delegations() });

	const list = useQuery<GoDelegation[]>({
		queryKey: authKeys.delegations(),
		queryFn: async () => unwrap(await client.delegations.list()),
	});
	const grant = useMutation<GoDelegation, Error, GrantDelegationInput>({
		mutationFn: async (input) => unwrap(await client.delegations.grant(input)),
		onSuccess: refresh,
	});
	const revoke = useMutation<null, Error, RevokeAgentInput>({
		mutationFn: async ({ id, reason }) => unwrap(await client.delegations.revoke(id, reason)),
		onSuccess: refresh,
	});
	return { list, grant, revoke };
}
