/**
 * kavachos
 * The Auth OS for AI Agents
 *
 * Identity, permissions, delegation, and audit for the agentic era.
 */

// Re-export submodules
export * from "./agent/index.js";
export * from "./analyzer/index.js";
export * from "./anomaly/index.js";
export * from "./approval/index.js";
export * from "./audit/index.js";
export * from "./auth/index.js";
export * from "./compliance/index.js";
export * from "./db/index.js";
export * from "./delegation/index.js";
export * from "./discovery/index.js";
export * from "./hooks/index.js";
export type { Kavach } from "./kavach.js";
export { createKavach } from "./kavach.js";
export { generateOpenAPISpec } from "./openapi.js";
export * from "./permission/index.js";
export * from "./session/index.js";
export * from "./policies/index.js";
export * from "./telemetry/index.js";
export * from "./tenant/index.js";
export * from "./trust/index.js";
export type {
	AgentFilter,
	AgentIdentity,
	AuthorizeRequest,
	AuthorizeResult,
	CreateAgentInput,
	DatabaseConfig,
	DelegateInput,
	DelegationChain,
	KavachConfig,
	KavachInstance,
	McpMiddleware,
	McpServer,
	McpServerInput,
	TokenValidationResult,
	UpdateAgentInput,
} from "./types.js";
