import type { AgentConfirmationConfig } from "./confirmation-http.js";

export interface AgentConfig {
	/** Enable agent identity management */
	enabled: boolean;
	/** Maximum agents per user */
	maxPerUser?: number;
	/** Default permissions for new agents */
	defaultPermissions?: string[];
	/** Log all agent actions to audit trail */
	auditAll?: boolean;
	/** Default token expiry duration */
	tokenExpiry?: string;
	/** Sender constrained agent tokens: DPoP (RFC 9449) proofs, certificate thumbprints (RFC 8705) or a custom proof, and whether unbound tokens are refused. See `docs/dpop-agent-tokens.mdx`. */
	confirmation?: AgentConfirmationConfig;
}
