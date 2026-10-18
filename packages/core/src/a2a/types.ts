/**
 * A2A (Agent-to-Agent) protocol types for TheAuth.
 * Implements the Google Agent2Agent protocol specification for agent interoperability.
 *
 * @see https://a2a-protocol.org/latest/specification/
 */

import type { AuthError, Result, TheAuthError } from "../mcp/types.js";

export * from "./schemas.js";
export type { AuthError, Result, TheAuthError };

export const A2A_PROTOCOL_VERSION = "0.3";
export const A2A_JSONRPC_VERSION = "2.0";
export const A2A_WELL_KNOWN_PATH = "/.well-known/agent.json";

export type A2ARole = "user" | "agent";

export type A2ATaskState =
	| "submitted"
	| "working"
	| "input-required"
	| "completed"
	| "failed"
	| "canceled"
	| "auth-required"
	| "rejected";

// Parts (content atoms inside messages/artifacts)

export interface A2ATextPart {
	type: "text";
	text: string;
}

export interface A2AFilePart {
	type: "file";
	fileUri: string;
	mimeType: string;
	name?: string;
}

export interface A2ADataPart {
	type: "data";
	mimeType: string;
	data: string; // base64-encoded
}

export type A2APart = A2ATextPart | A2AFilePart | A2ADataPart;

export interface A2AMessage {
	id: string;
	role: A2ARole;
	parts: A2APart[];
	createdAt: string;
	metadata?: Record<string, unknown>;
	referenceTaskIds?: string[];
}

export interface A2AArtifact {
	id: string;
	name?: string;
	mimeType?: string;
	parts: A2APart[];
	metadata?: Record<string, unknown>;
	createdAt: string;
}

export interface A2ATaskStatus {
	code: A2ATaskState;
	message?: string;
	progress?: number; // 0 to 100
}

export interface A2ATask {
	id: string;
	contextId: string;
	status: A2ATaskStatus;
	createdAt: string;
	updatedAt: string;
	history?: A2AMessage[];
	artifacts?: A2AArtifact[];
	metadata?: Record<string, unknown>;
}

export interface A2ATaskStatusUpdateEvent {
	taskId: string;
	contextId: string;
	newState: A2ATaskState;
	newStatus: A2ATaskStatus;
	timestamp: string;
	metadata?: Record<string, unknown>;
}

export interface A2ATaskArtifactUpdateEvent {
	taskId: string;
	contextId: string;
	artifactId: string;
	artifact: A2AArtifact;
	timestamp: string;
}

export type A2AStreamEvent =
	| { type: "task"; task: A2ATask }
	| { type: "message"; message: A2AMessage }
	| { type: "statusUpdate"; event: A2ATaskStatusUpdateEvent }
	| { type: "artifactUpdate"; event: A2ATaskArtifactUpdateEvent };

// Security Schemes (OpenAPI-style, per A2A spec)

export interface A2AApiKeySecurityScheme {
	type: "apiKey";
	name: string;
	in: "query" | "header" | "cookie";
	description?: string;
}

export interface A2AHttpSecurityScheme {
	type: "http";
	scheme: string;
	bearerFormat?: string;
	description?: string;
}

export interface A2AOAuth2Flow {
	authorizationUrl?: string;
	tokenUrl?: string;
	refreshUrl?: string;
	scopes: Record<string, string>;
}

export interface A2AOAuth2SecurityScheme {
	type: "oauth2";
	flows: {
		implicit?: A2AOAuth2Flow;
		password?: A2AOAuth2Flow;
		clientCredentials?: A2AOAuth2Flow;
		authorizationCode?: A2AOAuth2Flow;
		deviceCode?: A2AOAuth2Flow;
	};
	description?: string;
}

export interface A2AOidcSecurityScheme {
	type: "openIdConnect";
	openIdConnectUrl: string;
	description?: string;
}

export interface A2AMutualTlsSecurityScheme {
	type: "mutualTls";
	description?: string;
}

export type A2ASecurityScheme =
	| A2AApiKeySecurityScheme
	| A2AHttpSecurityScheme
	| A2AOAuth2SecurityScheme
	| A2AOidcSecurityScheme
	| A2AMutualTlsSecurityScheme;

export interface A2AAgentProvider {
	name: string;
	email?: string;
	url?: string;
}

export interface A2AAgentSkill {
	id: string;
	name: string;
	description: string;
	inputSchema?: Record<string, unknown>;
	outputSchema?: Record<string, unknown>;
	supportedMediaTypes?: string[];
	tags?: string[];
}

export interface A2AAgentCapabilities {
	streaming?: boolean;
	pushNotifications?: boolean;
	extendedAgentCard?: boolean;
}

export interface A2AAgentCardSignature {
	algorithm: string;
	signature: string;
	keyId: string;
}

export interface A2AAgentCard {
	id: string;
	name: string;
	description: string;
	version: string;
	protocolVersion: string;
	url: string;
	provider?: A2AAgentProvider;
	capabilities?: A2AAgentCapabilities;
	skills: A2AAgentSkill[];
	securitySchemes?: Record<string, A2ASecurityScheme>;
	security?: Array<Record<string, string[]>>;
	defaultInputModes?: string[];
	defaultOutputModes?: string[];
	documentationUrl?: string;
	signature?: A2AAgentCardSignature;
	metadata?: Record<string, unknown>;
}

export interface A2AJsonRpcRequest<P = unknown> {
	jsonrpc: "2.0";
	id: string | number;
	method: string;
	params: P;
}

export interface A2AJsonRpcResponse<R = unknown> {
	jsonrpc: "2.0";
	id: string | number;
	result?: R;
	error?: A2AJsonRpcError;
}

export interface A2AJsonRpcError {
	code: number;
	message: string;
	data?: unknown;
}

export const A2A_ERROR_CODES = {
	PARSE_ERROR: -32700,
	INVALID_REQUEST: -32600,
	METHOD_NOT_FOUND: -32601,
	INVALID_PARAMS: -32602,
	INTERNAL_ERROR: -32603,
	// A2A-specific codes (application-defined range)
	TASK_NOT_FOUND: -32001,
	AGENT_NOT_FOUND: -32002,
	AUTHENTICATION_REQUIRED: -32003,
	PERMISSION_DENIED: -32004,
	RATE_LIMITED: -32005,
	TASK_ALREADY_COMPLETED: -32006,
} as const;

export interface A2ASendMessageParams {
	message: A2AMessage;
	configuration?: A2ASendMessageConfiguration;
	metadata?: Record<string, unknown>;
}

export interface A2ASendMessageConfiguration {
	acceptedOutputModes?: string[];
	historyLength?: number;
	returnImmediately?: boolean;
}

export interface A2AGetTaskParams {
	id: string;
	historyLength?: number;
}

export interface A2ACancelTaskParams {
	id: string;
	metadata?: Record<string, unknown>;
}

export interface A2ASubscribeToTaskParams {
	id: string;
}

export const A2A_METHODS = {
	SEND_MESSAGE: "message/send",
	SEND_STREAMING_MESSAGE: "message/stream",
	GET_TASK: "tasks/get",
	CANCEL_TASK: "tasks/cancel",
} as const;

export interface A2ATaskHandler {
	/** Handle an incoming message and produce a task result */
	onMessage: (message: A2AMessage, config?: A2ASendMessageConfiguration) => Promise<A2ATask>;
	/** Handle task cancellation */
	onCancel?: (taskId: string) => Promise<A2ATask>;
	/** Handle streaming message, yields events instead of returning a task */
	onMessageStream?: (
		message: A2AMessage,
		config?: A2ASendMessageConfiguration,
	) => AsyncIterable<A2AStreamEvent>;
}

export interface A2AServerConfig {
	/** Agent card for this server */
	agentCard: A2AAgentCard;
	/** Handler for incoming tasks */
	handler: A2ATaskHandler;
	/** Validate an incoming auth token. Return the agent ID or null if invalid. */
	authenticate?: (request: Request) => Promise<string | null>;
	/** Called after each A2A interaction for audit logging */
	onAudit?: (event: A2AAuditEvent) => Promise<void>;
	/** In-memory or external task store. Defaults to in-memory Map. */
	taskStore?: A2ATaskStore;
}

export interface A2ATaskStore {
	get: (taskId: string) => Promise<A2ATask | undefined>;
	set: (taskId: string, task: A2ATask) => Promise<void>;
	delete: (taskId: string) => Promise<boolean>;
}

export interface A2AAuditEvent {
	method: string;
	agentId: string | null;
	taskId?: string;
	timestamp: string;
	success: boolean;
	error?: string;
}

export interface A2AClientConfig {
	/** Base URL of the remote A2A agent, or a discovered Agent Card */
	agent: string | A2AAgentCard;
	/** Auth token or function that returns a token */
	getAuthToken?: () => Promise<string> | string;
	/** Custom fetch implementation (for testing or proxying) */
	fetch?: typeof globalThis.fetch;
	/** Request timeout in milliseconds. Default: 30_000. */
	timeout?: number;
}

export interface A2AClient {
	/** Discover the remote agent's card from /.well-known/agent.json */
	discover: () => Promise<Result<A2AAgentCard>>;
	/** Send a message and get a task back */
	sendMessage: (params: A2ASendMessageParams) => Promise<Result<A2ATask>>;
	/** Get an existing task by ID */
	getTask: (params: A2AGetTaskParams) => Promise<Result<A2ATask>>;
	/** Cancel a running task */
	cancelTask: (params: A2ACancelTaskParams) => Promise<Result<A2ATask>>;
	/** Send a streaming message and receive SSE events */
	sendStreamingMessage: (params: A2ASendMessageParams) => AsyncIterable<A2AStreamEvent>;
}
