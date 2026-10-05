import type { GoCurrentToken } from "@glinr/theauth-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { unwrap, useTheAuthGoClient } from "./client-context.js";
import { authKeys } from "./keys.js";

/** The bearer token in use. The client must be built with `getToken`; a cookie session errors `auth.bearer_required`. */
export function useCurrentToken() {
	const client = useTheAuthGoClient();
	const qc = useQueryClient();
	const current = useQuery<GoCurrentToken>({
		queryKey: authKeys.currentToken(),
		queryFn: async () => unwrap(await client.apiTokens.current()),
		retry: false,
	});
	const revoke = useMutation<null, Error, void>({
		mutationFn: async () => unwrap(await client.apiTokens.revokeCurrent()),
		onSuccess: () => {
			qc.removeQueries({ queryKey: authKeys.currentToken() });
			return qc.invalidateQueries({ queryKey: authKeys.apiTokens() });
		},
	});
	return { current, revoke };
}
