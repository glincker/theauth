import { z } from "zod";

/** An SVID handed over in a request body. X.509 chains are PEM text, leaf first. */
export const SpiffePresentationSchema = z.discriminatedUnion("kind", [
	z.object({
		kind: z.literal("x509"),
		chain: z.string().min(1).max(32_768).describe("PEM certificates, leaf first"),
	}),
	z.object({
		kind: z.literal("jwt"),
		token: z.string().min(1).max(16_384).describe("Compact JWT-SVID"),
	}),
]);

export const SpiffeLinkSchema = z
	.object({
		spiffeId: z.string().min(1).max(2048).optional(),
		presentation: SpiffePresentationSchema.optional(),
	})
	.refine((v) => (v.spiffeId === undefined) !== (v.presentation === undefined), {
		message: "Send exactly one of spiffeId or presentation",
	});

export const SpiffeTokenRequestSchema = z.object({
	chain: z.string().min(1).max(32_768).describe("PEM certificates, leaf first"),
});

const SvidSchema = z.object({
	kind: z.enum(["x509", "jwt"]),
	expiresAt: z.string(),
	thumbprint: z.string().optional().describe("x5t#S256 of an X.509 leaf"),
});

export const SpiffeVerifyResultSchema = z.object({
	ok: z.boolean(),
	code: z.string().describe('"ok" or the failure code, for example expired or untrusted_chain'),
	reason: z.string().optional(),
	spiffeId: z.string().optional(),
	svid: SvidSchema.optional(),
	principal: z
		.object({ type: z.enum(["device", "agent"]), id: z.string(), name: z.string() })
		.optional(),
});

export const SpiffeIssuedTokenSchema = z.object({
	agentId: z.string(),
	token: z.string().describe("Agent token bound to the certificate (RFC 8705), returned once"),
	cnf: z.record(z.string()),
});
