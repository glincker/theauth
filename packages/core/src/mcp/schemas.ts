import { z } from "zod";
import {
	GRANT_TYPE_CLIENT_CREDENTIALS,
	GRANT_TYPE_JWT_BEARER,
	GRANT_TYPE_TOKEN_EXCHANGE,
} from "./grant-types.js";

// ─── Zod Schemas ────────────────────────────────────────────────────────────

export const McpClientRegistrationSchema = z.object({
	redirect_uris: z.array(z.string().url()),
	token_endpoint_auth_method: z
		.enum(["none", "client_secret_basic", "client_secret_post", "private_key_jwt"])
		.default("client_secret_basic")
		.optional(),
	grant_types: z
		.array(
			z.enum([
				"authorization_code",
				"refresh_token",
				GRANT_TYPE_CLIENT_CREDENTIALS,
				GRANT_TYPE_TOKEN_EXCHANGE,
				GRANT_TYPE_JWT_BEARER,
			]),
		)
		.default(["authorization_code"])
		.optional(),
	response_types: z
		.array(z.enum(["code"]))
		.default(["code"])
		.optional(),
	client_name: z.string().optional(),
	client_uri: z.string().url().optional(),
	logo_uri: z.string().url().optional(),
	scope: z.string().optional(),
	contacts: z.array(z.string()).optional(),
	tos_uri: z.string().url().optional(),
	policy_uri: z.string().url().optional(),
	software_id: z.string().optional(),
	software_version: z.string().optional(),
	jwks: z.object({ keys: z.array(z.record(z.string(), z.unknown())).min(1) }).optional(),
	jwks_uri: z.string().url().optional(),
});

export const McpAuthorizeRequestSchema = z.object({
	response_type: z.literal("code"),
	client_id: z.string().min(1),
	redirect_uri: z.string().min(1),
	scope: z.string().optional(),
	state: z.string().optional(),
	code_challenge: z.string().min(43).max(128),
	code_challenge_method: z.literal("S256"),
	/** RFC 8707 resource indicator. Required: tokens are always audience-bound. */
	resource: z.string().url(),
});

export const McpTokenRequestSchema = z.discriminatedUnion("grant_type", [
	z.object({
		grant_type: z.literal("authorization_code"),
		code: z.string().min(1),
		redirect_uri: z.string().min(1),
		client_id: z.string().min(1),
		client_secret: z.string().optional(),
		code_verifier: z.string().min(43).max(128),
		resource: z.string().url(),
	}),
	z.object({
		grant_type: z.literal("refresh_token"),
		refresh_token: z.string().min(1),
		client_id: z.string().min(1),
		client_secret: z.string().optional(),
		scope: z.string().optional(),
		resource: z.string().url().optional(),
	}),
	z.object({
		grant_type: z.literal(GRANT_TYPE_CLIENT_CREDENTIALS),
		client_id: z.string().min(1),
		client_secret: z.string().optional(),
		scope: z.string().optional(),
		resource: z.string().url().optional(),
	}),
	z.object({
		grant_type: z.literal(GRANT_TYPE_TOKEN_EXCHANGE),
		client_id: z.string().min(1),
		client_secret: z.string().optional(),
		subject_token: z.string().min(1),
		subject_token_type: z.string().min(1),
		actor_token: z.string().min(1).optional(),
		actor_token_type: z.string().min(1).optional(),
		requested_token_type: z.string().min(1).optional(),
		scope: z.string().optional(),
		resource: z.string().url().optional(),
		audience: z.string().url().optional(),
	}),
	z.object({
		grant_type: z.literal(GRANT_TYPE_JWT_BEARER),
		client_id: z.string().min(1),
		client_secret: z.string().optional(),
		assertion: z.string().min(1),
		scope: z.string().optional(),
		resource: z.string().url().optional(),
	}),
]);

export type McpTokenRequestParsed = z.infer<typeof McpTokenRequestSchema>;
