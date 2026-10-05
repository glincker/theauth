import type { ListApiTokensOptions } from "@glinr/theauth-client";

export const authKeys = {
	all: ["theauth"] as const,
	session: () => [...authKeys.all, "session"] as const,
	sessions: () => [...authKeys.all, "sessions"] as const,
	passkeys: () => [...authKeys.all, "passkeys"] as const,
	totp: () => [...authKeys.all, "totp"] as const,
	apiTokens: () => [...authKeys.all, "api-tokens"] as const,
	apiTokenList: (options: ListApiTokensOptions) =>
		[...authKeys.apiTokens(), options.all ?? false, options.ownerId ?? null] as const,
	deviceRequest: (userCode: string) => [...authKeys.all, "device-request", userCode] as const,
	bootstrap: () => [...authKeys.all, "bootstrap"] as const,
};
