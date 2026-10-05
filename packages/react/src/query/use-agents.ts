import type { GoAgent, RegisterAgentInput, RegisteredAgent } from "@glinr/theauth-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { unwrap, useTheAuthGoClient } from "./client-context.js";
import { authKeys } from "./keys.js";

export interface RevokeAgentInput {
	id: string;
	reason?: string;
}

/** The signed-in user's registered agents. Register returns the secret once. */
export function useAgents() {
	const client = useTheAuthGoClient();
	const qc = useQueryClient();
	const refresh = () => qc.invalidateQueries({ queryKey: authKeys.agents() });

	const list = useQuery<GoAgent[]>({
		queryKey: authKeys.agents(),
		queryFn: async () => unwrap(await client.agents.list()),
	});
	const register = useMutation<RegisteredAgent, Error, RegisterAgentInput>({
		mutationFn: async (input) => unwrap(await client.agents.register(input)),
		onSuccess: refresh,
	});
	const revoke = useMutation<null, Error, RevokeAgentInput>({
		mutationFn: async ({ id, reason }) => unwrap(await client.agents.revoke(id, reason)),
		onSuccess: () => {
			void qc.invalidateQueries({ queryKey: authKeys.delegations() });
			return refresh();
		},
	});
	return { list, register, revoke };
}
