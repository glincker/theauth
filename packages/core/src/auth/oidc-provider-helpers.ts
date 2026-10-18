import * as jose from "jose";
import { z } from "zod";
import { randomBytesHex, sha256 } from "../crypto/web-crypto.js";
import type { TheAuthError } from "../mcp/types.js";

export const registerClientSchema = z.object({
	clientName: z.string().min(1, "clientName must not be empty"),
	redirectUris: z.array(z.string().url()).min(1, "at least one redirectUri is required"),
	grantTypes: z
		.array(z.enum(["authorization_code", "refresh_token"]))
		.default(["authorization_code", "refresh_token"])
		.optional(),
	responseTypes: z
		.array(z.enum(["code"]))
		.default(["code"])
		.optional(),
	scopes: z.array(z.string()).optional(),
	tokenEndpointAuthMethod: z
		.enum(["client_secret_post", "client_secret_basic"])
		.default("client_secret_post")
		.optional(),
	postLogoutRedirectUris: z.array(z.string().url()).optional(),
	backchannelLogoutUri: z.string().url().optional(),
});

export const authorizeSchema = z.object({
	clientId: z.string().min(1),
	redirectUri: z.string().min(1),
	responseType: z.literal("code"),
	scope: z.string().min(1),
	state: z.string().optional(),
	nonce: z.string().optional(),
	codeChallenge: z.string().optional(),
	codeChallengeMethod: z.enum(["S256"]).optional(),
	userId: z.string().min(1),
	sessionId: z.string().min(1).optional(),
});

export const tokenSchema = z.discriminatedUnion("grantType", [
	z.object({
		grantType: z.literal("authorization_code"),
		code: z.string().min(1),
		redirectUri: z.string().min(1),
		codeVerifier: z.string().optional(),
		clientId: z.string().min(1),
		clientSecret: z.string().optional(),
	}),
	z.object({
		grantType: z.literal("refresh_token"),
		refreshToken: z.string().min(1),
		clientId: z.string().min(1),
		clientSecret: z.string().optional(),
	}),
]);

export const DEFAULT_ACCESS_TOKEN_TTL = 3600;
export const DEFAULT_REFRESH_TOKEN_TTL = 86400 * 30;
export const DEFAULT_AUTH_CODE_TTL = 600;
export const DEFAULT_ID_TOKEN_TTL = 3600;
export const DEFAULT_SIGNING_ALG = "RS256";
export const DEFAULT_SCOPES = ["openid", "profile", "email"];
export const CLIENT_ID_BYTE_LENGTH = 16;
export const CLIENT_SECRET_BYTE_LENGTH = 32;
export const AUTH_CODE_BYTE_LENGTH = 32;
export const REFRESH_TOKEN_BYTE_LENGTH = 32;

export function makeError(
	code: string,
	message: string,
	details?: Record<string, unknown>,
): TheAuthError {
	return { code, message, ...(details !== undefined ? { details } : {}) };
}

export function generateRandomHex(bytes: number): string {
	return randomBytesHex(bytes);
}

export async function hashSecret(raw: string): Promise<string> {
	return sha256(raw);
}

export async function computeS256Challenge(codeVerifier: string): Promise<string> {
	const encoder = new TextEncoder();
	const data = encoder.encode(codeVerifier);
	const digest = await globalThis.crypto.subtle.digest("SHA-256", data);
	return jose.base64url.encode(new Uint8Array(digest));
}
