/**
 * A2A Zod schemas (runtime validation for the A2A protocol types in ./types.ts).
 */

import { z } from "zod";

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
