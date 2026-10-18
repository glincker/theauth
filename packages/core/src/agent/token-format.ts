/**
 * Agent token format. New tokens are `ta_` plus 43 base64url characters (32 random bytes).
 * Tokens issued before the rename start with `kv_` and stay valid: lookups are by SHA-256
 * hash, so the prefix only gates obviously foreign strings and labels the stored prefix.
 */
export const AGENT_TOKEN_PREFIX = "ta_";

/** Prefixes of tokens issued by earlier releases. Still accepted, never generated. */
export const LEGACY_AGENT_TOKEN_PREFIXES = ["kv_"] as const;

/** Length of the stored lookup prefix: the token prefix plus 8 characters of the secret. */
export const AGENT_TOKEN_LOOKUP_PREFIX_LENGTH = AGENT_TOKEN_PREFIX.length + 8;

/** True when `token` carries the current or a legacy agent token prefix. */
export function isAgentToken(token: string): boolean {
	if (typeof token !== "string") return false;
	if (token.startsWith(AGENT_TOKEN_PREFIX)) return true;
	return LEGACY_AGENT_TOKEN_PREFIXES.some((p) => token.startsWith(p));
}

/** The short, non-secret prefix stored for identification in lists and logs. */
export function agentTokenLookupPrefix(token: string): string {
	return token.slice(0, AGENT_TOKEN_LOOKUP_PREFIX_LENGTH);
}
