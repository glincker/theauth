import type {
	GoApiToken,
	ListApiTokensOptions,
	MintApiTokenInput,
	MintedApiToken,
} from "@glinr/theauth-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { unwrap, useTheAuthGoClient } from "./client-context.js";
import { authKeys } from "./keys.js";

/** Personal API tokens. `options.all` and `options.ownerId` are admin-only filters. */
export function useApiTokens(options: ListApiTokensOptions = {}) {
	const client = useTheAuthGoClient();
	const qc = useQueryClient();
	const refresh = () => qc.invalidateQueries({ queryKey: authKeys.apiTokens() });

	const list = useQuery<GoApiToken[]>({
		queryKey: authKeys.apiTokenList(options),
		queryFn: async () => unwrap(await client.apiTokens.list(options)),
	});
	const mint = useMutation<MintedApiToken, Error, MintApiTokenInput>({
		mutationFn: async (input) => unwrap(await client.apiTokens.mint(input)),
		onSuccess: refresh,
	});
	const revoke = useMutation<null, Error, string>({
		mutationFn: async (id) => unwrap(await client.apiTokens.revoke(id)),
		onSuccess: refresh,
	});

	return { list, mint, revoke };
}
