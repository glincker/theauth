import type {
	ApiTokenKind,
	GoApiToken,
	ListApiTokensOptions,
	MintApiTokenInput,
	MintedApiToken,
} from "@glinr/theauth-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { unwrap, useTheAuthGoClient } from "./client-context.js";
import { authKeys } from "./keys.js";

export interface UseApiTokensOptions extends ListApiTokensOptions {
	/** Client-side filter; the server returns both kinds. Cache is shared across kinds. */
	kind?: ApiTokenKind;
}

/** A token with no kind is personal. */
export function tokenKind(token: Pick<GoApiToken, "kind">): ApiTokenKind {
	return token.kind === "agent" ? "agent" : "personal";
}

/** API tokens. `options.all` and `options.ownerId` are admin-only filters. */
export function useApiTokens({ kind, ...options }: UseApiTokensOptions = {}) {
	const client = useTheAuthGoClient();
	const qc = useQueryClient();
	const refresh = () => qc.invalidateQueries({ queryKey: authKeys.apiTokens() });

	const list = useQuery<GoApiToken[]>({
		queryKey: authKeys.apiTokenList(options),
		queryFn: async () => unwrap(await client.apiTokens.list(options)),
		select: (tokens) => (kind ? tokens.filter((t) => tokenKind(t) === kind) : tokens),
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

export type MintAgentTokenInput = Omit<MintApiTokenInput, "kind" | "serviceAccount" | "ownerId">;

/** Agent tokens: short-lived, bound to the signed-in human's abilities. Mint, list, revoke. */
export function useAgentTokens(options: Omit<UseApiTokensOptions, "kind"> = {}) {
	const { list, revoke } = useApiTokens({ ...options, kind: "agent" });
	const client = useTheAuthGoClient();
	const qc = useQueryClient();
	const mintAgent = useMutation<MintedApiToken, Error, MintAgentTokenInput>({
		mutationFn: async (input) => unwrap(await client.apiTokens.mint({ ...input, kind: "agent" })),
		onSuccess: () => qc.invalidateQueries({ queryKey: authKeys.apiTokens() }),
	});
	return { list, mint: mintAgent, revoke };
}
