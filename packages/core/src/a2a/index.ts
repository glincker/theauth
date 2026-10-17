// A2A (Agent-to-Agent) Protocol Module
//
// Implements Google's Agent2Agent protocol for agent interoperability.
// Covers Agent Card creation/validation/signing, JSON-RPC server,
// client discovery, and SSE streaming.
//
// @see https://a2a-protocol.org/latest/specification/

export type {
	CreateAgentCardInput,
	SignAgentCardOptions,
	VerifyAgentCardOptions,
} from "./agent-card.js";
export {
	createAgentCard,
	signAgentCard,
	validateAgentCard,
	verifyAgentCard,
} from "./agent-card.js";

// A2A client (call remote agents)
export { createA2AClient } from "./client.js";
export type { A2AServer } from "./server.js";
// A2A server (accept incoming agent requests)
export { createA2AServer } from "./server.js";

export type {
	A2AAgentCapabilities,
	A2AAgentCard,
	A2AAgentCardSignature,
	A2AAgentProvider,
	A2AAgentSkill,
	A2AApiKeySecurityScheme,
	A2AArtifact,
	A2AAuditEvent,
	A2ACancelTaskParams,
	A2AClient,
	A2AClientConfig,
	A2ADataPart,
	A2AFilePart,
	A2AGetTaskParams,
	A2AHttpSecurityScheme,
	A2AJsonRpcError,
	A2AJsonRpcRequest,
	A2AJsonRpcResponse,
	A2AMessage,
	A2AMutualTlsSecurityScheme,
	A2AOAuth2Flow,
	A2AOAuth2SecurityScheme,
	A2AOidcSecurityScheme,
	A2APart,
	A2ARole,
	A2ASecurityScheme,
	A2ASendMessageConfiguration,
	A2ASendMessageParams,
	A2AServerConfig,
	A2AStreamEvent,
	A2ATask,
	A2ATaskArtifactUpdateEvent,
	A2ATaskHandler,
	A2ATaskState,
	A2ATaskStatus,
	A2ATaskStatusUpdateEvent,
	A2ATaskStore,
	A2ATextPart,
} from "./types.js";
export {
	A2A_ERROR_CODES,
	A2A_JSONRPC_VERSION,
	A2A_METHODS,
	A2A_PROTOCOL_VERSION,
	A2A_WELL_KNOWN_PATH,
	A2AAgentCapabilitiesSchema,
	A2AAgentCardSchema,
	A2AAgentCardSignatureSchema,
	A2AAgentProviderSchema,
	A2AAgentSkillSchema,
	A2AApiKeySecuritySchemeSchema,
	A2AArtifactSchema,
	A2ACancelTaskParamsSchema,
	A2ADataPartSchema,
	A2AFilePartSchema,
	A2AGetTaskParamsSchema,
	A2AHttpSecuritySchemeSchema,
	A2AJsonRpcRequestSchema,
	A2AMessageSchema,
	A2AMutualTlsSecuritySchemeSchema,
	A2AOAuth2FlowSchema,
	A2AOAuth2SecuritySchemeSchema,
	A2AOidcSecuritySchemeSchema,
	A2APartSchema,
	A2ASecuritySchemeSchema,
	A2ASendMessageConfigurationSchema,
	A2ASendMessageParamsSchema,
	A2ATaskSchema,
	A2ATaskStateSchema,
	A2ATaskStatusSchema,
	A2ATextPartSchema,
} from "./types.js";
