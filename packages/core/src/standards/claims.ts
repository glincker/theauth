/**
 * IETF agentic JWT claim name constants.
 *
 * Sources:
 *   - draft-goswami-agentic-jwt-00
 *   - draft-liu-agent-operation-authorization-01
 *
 * These constants are off by default. Set `emitAgenticJwtClaims: true` in
 * KavachConfig to include them in issued tokens.
 */

// ---------------------------------------------------------------------------
// Named types
// ---------------------------------------------------------------------------

/**
 * Operational mode of an agent within a delegation chain.
 *
 * - `autonomous`  — no human-in-the-loop; the agent acts on its own behalf.
 * - `delegated`   — the agent is acting under explicit delegation from another principal.
 * - `supervised`  — the agent acts autonomously but requires human approval for sensitive ops.
 */
export type AgentType = "autonomous" | "delegated" | "supervised";

/**
 * Trust tier band assigned at token issuance, derived from the numeric trust
 * score. Matches the five-level model in KavachOS trust scoring.
 *
 * Mapping (inclusive lower bound):
 *   score 0–19  → "unverified"
 *   score 20–39 → "low"
 *   score 40–59 → "standard"
 *   score 60–79 → "elevated"
 *   score 80+   → "high"
 */
export type TrustTier = "unverified" | "low" | "standard" | "elevated" | "high";

// ---------------------------------------------------------------------------
// Claim name constants
// ---------------------------------------------------------------------------

/**
 * Registered claim names for agentic JWTs.
 *
 * All names are string literals so they can be used directly as JWT payload
 * keys. Consuming code should index into issued token payloads using these
 * constants rather than raw string literals.
 */
export const AGENTIC_JWT_CLAIMS = {
	/**
	 * Stable identifier of the agent making the call.
	 *
	 * @see draft-goswami-agentic-jwt-00 §3.1
	 */
	AGENT_ID: "agent_id",

	/**
	 * Operational mode of the agent: `autonomous`, `delegated`, or `supervised`.
	 *
	 * @see draft-goswami-agentic-jwt-00 §3.2
	 */
	AGENT_TYPE: "agent_type",

	/**
	 * Subject principal the agent is acting on behalf of (human user or upstream agent).
	 *
	 * @see draft-goswami-agentic-jwt-00 §3.3
	 */
	ON_BEHALF_OF: "on_behalf_of",

	/**
	 * Actor claim per RFC 8693. Identifies the current actor in an
	 * impersonation or delegation chain.
	 *
	 * @see draft-goswami-agentic-jwt-00 §3.4
	 * @see RFC 8693
	 */
	ACT: "act",

	/**
	 * Authorized future actors for delegation chains (RFC 8693 `may_act`).
	 *
	 * @see draft-goswami-agentic-jwt-00 §3.5
	 * @see RFC 8693
	 */
	MAY_ACT: "may_act",

	/**
	 * Trust score band at token issuance (e.g. `standard`, `elevated`).
	 *
	 * @see draft-goswami-agentic-jwt-00 §3.6
	 */
	TRUST_TIER: "trust_tier",

	/**
	 * Correlation id for tracing this token back to an entry in the audit log.
	 *
	 * @see draft-goswami-agentic-jwt-00 §3.7
	 */
	AUDIT_REF: "audit_ref",

	/**
	 * Per-tool budget or rate constraints encoded as a structured object.
	 *
	 * @see draft-goswami-agentic-jwt-00 §3.8
	 */
	TOOL_CONSTRAINTS: "tool_constraints",

	/**
	 * Workload Identity Token (WIT). Present only when three-layer cryptographic
	 * binding is active (draft-liu §4.2). Absent in standard issuance paths.
	 *
	 * @see draft-liu-agent-operation-authorization-01 §4.2
	 * TODO(v3): populate from WIT issuance when three-layer binding is implemented.
	 */
	WORKLOAD_BINDING: "wit",

	/**
	 * The scoped operation this token authorizes (e.g. `read:documents`).
	 *
	 * @see draft-liu-agent-operation-authorization-01 §4.3
	 */
	OPERATION: "operation",
} as const;

// ---------------------------------------------------------------------------
// Payload shape
// ---------------------------------------------------------------------------

/**
 * Optional shape of agentic JWT claims within a token payload.
 *
 * All fields are optional because they are only emitted when
 * `emitAgenticJwtClaims` is enabled and the relevant context is available
 * on the issuance path.
 */
export interface AgenticJwtClaims {
	/** Stable agent identifier. */
	agent_id?: string;
	/** Operational mode of the agent. */
	agent_type?: AgentType;
	/** Principal the agent is acting for. */
	on_behalf_of?: string;
	/** RFC 8693 actor claim (current actor in a delegation chain). */
	act?: Record<string, unknown>;
	/** RFC 8693 may_act claim (authorized future actors). */
	may_act?: Record<string, unknown>;
	/** Trust tier band at issuance time. */
	trust_tier?: TrustTier;
	/** Audit log correlation id. */
	audit_ref?: string;
	/** Per-tool budget or rate constraints. */
	tool_constraints?: Record<string, unknown>;
	/**
	 * Workload Identity Token.
	 * Absent unless three-layer binding is active.
	 * TODO(v3): populate when draft-liu three-layer binding is implemented.
	 */
	wit?: string;
	/** Scoped operation this token authorizes. */
	operation?: string;
}
