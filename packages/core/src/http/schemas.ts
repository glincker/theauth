import { z } from "zod";
import { AgentConfirmationSchema } from "../agent/confirmation.js";
import { InputSourcesSchema } from "../audit/provenance-wire.js";

const PermissionConstraintsSchema = z.object({
	maxCallsPerHour: z.number().int().positive().optional(),
	allowedArgPatterns: z.array(z.string()).optional(),
	requireApproval: z.boolean().optional(),
	timeWindow: z.object({ start: z.string(), end: z.string() }).optional(),
	ipAllowlist: z.array(z.string()).optional(),
});

export const PermissionSchema = z.object({
	resource: z.string().min(1),
	actions: z.array(z.string().min(1)).min(1),
	constraints: PermissionConstraintsSchema.optional(),
});

export const CreateAgentSchema = z.object({
	ownerId: z.string().min(1),
	name: z.string().min(1),
	type: z.enum(["autonomous", "delegated", "service"]),
	permissions: z.array(PermissionSchema).min(1),
	expiresAt: z.coerce.date().optional(),
	metadata: z.record(z.unknown()).optional(),
	cnf: AgentConfirmationSchema.optional().describe(
		"Bind the agent token to a key or certificate (RFC 7800), for example { jkt: <DPoP key thumbprint> }",
	),
});

export const RotateAgentSchema = z.object({
	cnf: AgentConfirmationSchema.nullable()
		.optional()
		.describe(
			"New binding for the rotated token. null makes it a plain bearer token. Omit to keep the current one.",
		),
});

export const IntrospectAgentTokenSchema = z.object({ token: z.string().min(1) });

export const UpdateAgentSchema = z.object({
	name: z.string().min(1).optional(),
	permissions: z.array(PermissionSchema).optional(),
	expiresAt: z.coerce.date().optional(),
	metadata: z.record(z.unknown()).optional(),
});

export const AuthorizeSchema = z.object({
	agentId: z.string().min(1),
	action: z.string().min(1),
	resource: z.string().min(1),
	arguments: z.record(z.unknown()).optional(),
	approvalId: z.string().min(1).optional(),
	/** Where the inputs of the call came from. Hashed and recorded in the audit row, content is never stored. */
	inputs: InputSourcesSchema.optional(),
});

export const AuthorizeByTokenSchema = z.object({
	action: z.string().min(1),
	resource: z.string().min(1),
	arguments: z.record(z.unknown()).optional(),
	approvalId: z.string().min(1).optional(),
	/** Where the inputs of the call came from. Hashed and recorded in the audit row, content is never stored. */
	inputs: InputSourcesSchema.optional(),
});

export const DelegateSchema = z.object({
	fromAgent: z.string().min(1),
	toAgent: z.string().min(1),
	permissions: z.array(PermissionSchema).min(1),
	expiresAt: z.coerce.date(),
	maxDepth: z.number().int().positive().optional(),
});

export const ExplainSchema = z.object({
	agentId: z.string().min(1),
	action: z.string().min(1),
	resource: z.string().min(1),
	arguments: z.record(z.unknown()).optional(),
	context: z.object({ ip: z.string().optional(), userAgent: z.string().optional() }).optional(),
	at: z.coerce.date().optional(),
	runHooks: z.boolean().optional(),
});
