/** IETF agentic JWT claim names (draft-goswami-agentic-jwt-00, draft-liu-agent-operation-authorization-01). These constants are off by default. */

/** Operational mode: `autonomous` (no human in the loop), `delegated`, or `supervised`. */
export type AgentType = "autonomous" | "delegated" | "supervised";

/** Trust tier band at issuance, derived from the 0-100 trust score. */
export type TrustTier = "unverified" | "low" | "standard" | "elevated" | "high";

/** Registered claim names for agentic JWTs. Use them as payload keys when reading issued tokens. */
export const AGENTIC_JWT_CLAIMS = {
	/** Stable identifier of the calling agent. @see draft-goswami-agentic-jwt-00 §3.1 */
	AGENT_ID: "agent_id",

	/** Operational mode of the agent. @see draft-goswami-agentic-jwt-00 §3.2 */
	AGENT_TYPE: "agent_type",

	/** Principal the agent acts on behalf of (human user or upstream agent). @see draft-goswami-agentic-jwt-00 §3.3 */
	ON_BEHALF_OF: "on_behalf_of",

	/** Actor claim for the current actor in an impersonation or delegation chain. @see draft-goswami-agentic-jwt-00 §3.4, RFC 8693 */
	ACT: "act",

	/** Authorized future actors for delegation chains (`may_act`). @see draft-goswami-agentic-jwt-00 §3.5, RFC 8693 */
	MAY_ACT: "may_act",

	/** Trust score band at token issuance. @see draft-goswami-agentic-jwt-00 §3.6 */
	TRUST_TIER: "trust_tier",

	/** Correlation id linking the token to an audit log entry. @see draft-goswami-agentic-jwt-00 §3.7 */
	AUDIT_REF: "audit_ref",

	/** Per-tool budget or rate constraints as a structured object. @see draft-goswami-agentic-jwt-00 §3.8 */
	TOOL_CONSTRAINTS: "tool_constraints",

	/**
	 * Workload Identity Token (WIT). Present only when three-layer cryptographic binding is active (draft-liu §4.2). Absent in standard issuance paths.
	 *
	 * @see draft-liu-agent-operation-authorization-01 §4.2
	 * TODO(v3): populate from WIT issuance when three-layer binding is implemented.
	 */
	WORKLOAD_BINDING: "wit",

	/** The scoped operation this token authorizes (e.g. `read:documents`). @see draft-liu-agent-operation-authorization-01 §4.3 */
	OPERATION: "operation",
} as const;

/** Optional agentic claims in a token payload. Emitted only when `emitAgenticJwtClaims` is enabled and the value is present. */
export interface AgenticJwtClaims {
	agent_id?: string;
	agent_type?: AgentType;
	on_behalf_of?: string;
	/** RFC 8693 actor claim (current actor in a delegation chain). */
	act?: Record<string, unknown>;
	/** RFC 8693 may_act claim (authorized future actors). */
	may_act?: Record<string, unknown>;
	trust_tier?: TrustTier;
	audit_ref?: string;
	tool_constraints?: Record<string, unknown>;
	/** Workload Identity Token. Absent unless three-layer binding is active. TODO(v3): populate when draft-liu three-layer binding is implemented. */
	wit?: string;
	operation?: string;
}
