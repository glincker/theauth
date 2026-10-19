import { z } from "zod";
import { timingSafeEqual } from "../mcp/utils.js";

/**
 * Sender constraint of an agent token, stored as a confirmation claim (RFC 7800).
 * Each member names a way to prove possession and holds the thumbprint of the key or certificate:
 * `jkt` is the RFC 7638 thumbprint of a DPoP key (RFC 9449), `x5t#S256` the thumbprint of a client
 * certificate for mutual TLS (RFC 8705). When several members are set, every one must be proven.
 */
export type AgentConfirmation = Record<string, string>;

/** DPoP key thumbprint member (RFC 9449 section 6). */
export const CNF_JKT = "jkt";
/** Certificate thumbprint member (RFC 8705 section 3.1). */
export const CNF_X5T_S256 = "x5t#S256";

const MEMBER_NAME = /^[A-Za-z0-9#_-]{1,32}$/;
const THUMBPRINT = /^[A-Za-z0-9_-]{16,128}$/;
const MAX_MEMBERS = 4;

/** Shape of `cnf` in create and rotate requests. At least one member, thumbprints in base64url. */
export const AgentConfirmationSchema = z
	.record(z.string().regex(MEMBER_NAME), z.string().regex(THUMBPRINT))
	.refine((value) => {
		const size = Object.keys(value).length;
		return size >= 1 && size <= MAX_MEMBERS;
	}, "cnf needs between 1 and 4 members");

/** Validate a confirmation claim from outside, or throw. */
export function parseConfirmation(input: unknown): AgentConfirmation {
	const parsed = AgentConfirmationSchema.safeParse(input);
	if (!parsed.success) {
		throw new Error(
			`Invalid agent confirmation: ${parsed.error.issues[0]?.message ?? "bad shape"}`,
		);
	}
	return parsed.data;
}

/**
 * Read a stored `cnf` value. Nothing stored means a plain bearer token. A value that no longer parses
 * becomes a binding nobody can prove (member `unreadable`), so a damaged row fails closed instead of
 * silently turning into an unbound token.
 */
export function readStoredConfirmation(raw: unknown): AgentConfirmation | undefined {
	if (raw === null || raw === undefined) return undefined;
	const parsed = AgentConfirmationSchema.safeParse(raw);
	return parsed.success ? parsed.data : { unreadable: "unreadable-binding" };
}

export type ConfirmationVerdict = "ok" | "required" | "failed";

/**
 * Compare the binding of a token with the proofs a request presented.
 * - `required`: the token is bound and the request proved nothing.
 * - `failed`: a proof is missing for one member, or does not match.
 * No binding means `ok`: the token is a plain bearer token.
 */
export function confirmationVerdict(
	bound: AgentConfirmation | undefined,
	presented: AgentConfirmation | undefined,
): ConfirmationVerdict {
	if (!bound || Object.keys(bound).length === 0) return "ok";
	if (!presented || Object.keys(presented).length === 0) return "required";
	for (const [member, expected] of Object.entries(bound)) {
		const actual = presented[member];
		if (typeof actual !== "string" || !timingSafeEqual(expected, actual)) return "failed";
	}
	return "ok";
}
