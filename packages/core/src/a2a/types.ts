/**
 * A2A (Agent-to-Agent) protocol types for TheAuth.
 *
 * Implements the Google Agent2Agent protocol specification for
 * agent interoperability. Covers Agent Cards, JSON-RPC methods,
 * task lifecycle, message/artifact types, and authentication schemes.
 *
 * @see https://a2a-protocol.org/latest/specification/
 */

import { z } from "zod";
import type { KavachError, Result } from "../mcp/types.js";

export type { KavachError, Result };

// ─── Protocol Constants ─────────────────────────────────────────────────────

export const A2A_PROTOCOL_VERSION = "0.3";
export const A2A_JSONRPC_VERSION = "2.0";
export const A2A_WELL_KNOWN_PATH = "/.well-known/agent.json";

// ─── Roles & States ─────────────────────────────────────────────────────────

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

// ─── Parts (content atoms inside messages/artifacts) ─────────────────────────

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

// ─── Message ─────────────────────────────────────────────────────────────────

export interface A2AMessage {
	id: string;
	role: A2ARole;
	parts: A2APart[];
	createdAt: string;
	metadata?: Record<string, unknown>;
	referenceTaskIds?: string[];
}

// ─── Artifact ────────────────────────────────────────────────────────────────

export interface A2AArtifact {
	id: string;
	name?: string;
	mimeType?: string;
	parts: A2APart[];
	metadata?: Record<string, unknown>;
	createdAt: string;
}

// ─── Task Status ─────────────────────────────────────────────────────────────

export interface A2ATaskStatus {
	code: A2ATaskState;
	message?: string;
	progress?: number; // 0–100
}

// ─── Task ────────────────────────────────────────────────────────────────────

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

// ─── Streaming Events ────────────────────────────────────────────────────────

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

// ─── Security Schemes (OpenAPI-style, per A2A spec) ──────────────────────────

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

// ─── Agent Card ──────────────────────────────────────────────────────────────

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

// ─── JSON-RPC Envelope ───────────────────────────────────────────────────────

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

// ─── JSON-RPC Standard Error Codes ───────────────────────────────────────────

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

// ─── JSON-RPC Method Params ──────────────────────────────────────────────────

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

// ─── JSON-RPC Method Names ───────────────────────────────────────────────────

export const A2A_METHODS = {
	SEND_MESSAGE: "message/send",
	SEND_STREAMING_MESSAGE: "message/stream",
	GET_TASK: "tasks/get",
	CANCEL_TASK: "tasks/cancel",
} as const;

// ─── A2A Server Config ───────────────────────────────────────────────────────

export interface A2ATaskHandler {
	/** Handle an incoming message and produce a task result */
	onMessage: (message: A2AMessage, config?: A2ASendMessageConfiguration) => Promise<A2ATask>;
	/** Handle task cancellation */
	onCancel?: (taskId: string) => Promise<A2ATask>;
	/** Handle streaming message — yields events instead of returning a task */
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

// ─── A2A Client Config ───────────────────────────────────────────────────────

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

// ─── Zod Schemas ─────────────────────────────────────────────────────────────

export const A2ATextPartSchema = z.object({
	type: z.literal("text"),
	text: z.string(),
});

export const A2AFilePartSchema = z.object({
	type: z.literal("file"),
	fileUri: z.string(),
	mimeType: z.string(),
	name: z.string().optional(),
});

export const A2ADataPartSchema = z.object({
	type: z.literal("data"),
	mimeType: z.string(),
	data: z.string(),
});

export const A2APartSchema = z.discriminatedUnion("type", [
	A2ATextPartSchema,
	A2AFilePartSchema,
	A2ADataPartSchema,
]);

export const A2AMessageSchema = z.object({
	id: z.string().min(1),
	role: z.enum(["user", "agent"]),
	parts: z.array(A2APartSchema).min(1),
	createdAt: z.string(),
	metadata: z.record(z.unknown()).optional(),
	referenceTaskIds: z.array(z.string()).optional(),
});

export const A2ATaskStateSchema = z.enum([
	"submitted",
	"working",
	"input-required",
	"completed",
	"failed",
	"canceled",
	"auth-required",
	"rejected",
]);

export const A2ATaskStatusSchema = z.object({
	code: A2ATaskStateSchema,
	message: z.string().optional(),
	progress: z.number().min(0).max(100).optional(),
});

export const A2AArtifactSchema = z.object({
	id: z.string().min(1),
	name: z.string().optional(),
	mimeType: z.string().optional(),
	parts: z.array(A2APartSchema).min(1),
	metadata: z.record(z.unknown()).optional(),
	createdAt: z.string(),
});

export const A2ATaskSchema = z.object({
	id: z.string().min(1),
	contextId: z.string().min(1),
	status: A2ATaskStatusSchema,
	createdAt: z.string(),
	updatedAt: z.string(),
	history: z.array(A2AMessageSchema).optional(),
	artifacts: z.array(A2AArtifactSchema).optional(),
	metadata: z.record(z.unknown()).optional(),
});

export const A2AAgentSkillSchema = z.object({
	id: z.string().min(1),
	name: z.string().min(1),
	description: z.string(),
	inputSchema: z.record(z.unknown()).optional(),
	outputSchema: z.record(z.unknown()).optional(),
	supportedMediaTypes: z.array(z.string()).optional(),
	tags: z.array(z.string()).optional(),
});

export const A2AAgentProviderSchema = z.object({
	name: z.string().min(1),
	email: z.string().optional(),
	url: z.string().optional(),
});

export const A2AAgentCapabilitiesSchema = z.object({
	streaming: z.boolean().optional(),
	pushNotifications: z.boolean().optional(),
	extendedAgentCard: z.boolean().optional(),
});

const A2ASecuritySchemeBaseSchema = z.object({
	description: z.string().optional(),
});

export const A2AApiKeySecuritySchemeSchema = A2ASecuritySchemeBaseSchema.extend({
	type: z.literal("apiKey"),
	name: z.string().min(1),
	in: z.enum(["query", "header", "cookie"]),
});

export const A2AHttpSecuritySchemeSchema = A2ASecuritySchemeBaseSchema.extend({
	type: z.literal("http"),
	scheme: z.string().min(1),
	bearerFormat: z.string().optional(),
});

export const A2AOAuth2FlowSchema = z.object({
	authorizationUrl: z.string().optional(),
	tokenUrl: z.string().optional(),
	refreshUrl: z.string().optional(),
	scopes: z.record(z.string()),
});

export const A2AOAuth2SecuritySchemeSchema = A2ASecuritySchemeBaseSchema.extend({
	type: z.literal("oauth2"),
	flows: z.object({
		implicit: A2AOAuth2FlowSchema.optional(),
		password: A2AOAuth2FlowSchema.optional(),
		clientCredentials: A2AOAuth2FlowSchema.optional(),
		authorizationCode: A2AOAuth2FlowSchema.optional(),
		deviceCode: A2AOAuth2FlowSchema.optional(),
	}),
});

export const A2AOidcSecuritySchemeSchema = A2ASecuritySchemeBaseSchema.extend({
	type: z.literal("openIdConnect"),
	openIdConnectUrl: z.string().min(1),
});

export const A2AMutualTlsSecuritySchemeSchema = A2ASecuritySchemeBaseSchema.extend({
	type: z.literal("mutualTls"),
});

export const A2ASecuritySchemeSchema = z.discriminatedUnion("type", [
	A2AApiKeySecuritySchemeSchema,
	A2AHttpSecuritySchemeSchema,
	A2AOAuth2SecuritySchemeSchema,
	A2AOidcSecuritySchemeSchema,
	A2AMutualTlsSecuritySchemeSchema,
]);

export const A2AAgentCardSignatureSchema = z.object({
	algorithm: z.string().min(1),
	signature: z.string().min(1),
	keyId: z.string().min(1),
});

export const A2AAgentCardSchema = z.object({
	id: z.string().min(1),
	name: z.string().min(1),
	description: z.string(),
	version: z.string().min(1),
	protocolVersion: z.string().min(1),
	url: z.string().url(),
	provider: A2AAgentProviderSchema.optional(),
	capabilities: A2AAgentCapabilitiesSchema.optional(),
	skills: z.array(A2AAgentSkillSchema).min(1),
	securitySchemes: z.record(A2ASecuritySchemeSchema).optional(),
	security: z.array(z.record(z.array(z.string()))).optional(),
	defaultInputModes: z.array(z.string()).optional(),
	defaultOutputModes: z.array(z.string()).optional(),
	documentationUrl: z.string().url().optional(),
	signature: A2AAgentCardSignatureSchema.optional(),
	metadata: z.record(z.unknown()).optional(),
});

export const A2ASendMessageConfigurationSchema = z.object({
	acceptedOutputModes: z.array(z.string()).optional(),
	historyLength: z.number().int().min(0).optional(),
	returnImmediately: z.boolean().optional(),
});

export const A2ASendMessageParamsSchema = z.object({
	message: A2AMessageSchema,
	configuration: A2ASendMessageConfigurationSchema.optional(),
	metadata: z.record(z.unknown()).optional(),
});

export const A2AGetTaskParamsSchema = z.object({
	id: z.string().min(1),
	historyLength: z.number().int().min(0).optional(),
});

export const A2ACancelTaskParamsSchema = z.object({
	id: z.string().min(1),
	metadata: z.record(z.unknown()).optional(),
});

export const A2AJsonRpcRequestSchema = z.object({
	jsonrpc: z.literal("2.0"),
	id: z.union([z.string(), z.number()]),
	method: z.string().min(1),
	params: z.unknown(),
});
