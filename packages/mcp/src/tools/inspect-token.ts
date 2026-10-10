import { z } from "zod";
import { defineTool, failure, success } from "./define.js";

const AGENT_TOKEN_PREFIX = "kv_";
const KNOWN_CLAIMS = new Set([
	"iss",
	"sub",
	"aud",
	"scope",
	"scp",
	"client_id",
	"jti",
	"iat",
	"nbf",
	"exp",
	"cnf",
]);
const WEAK_ALGS = new Set(["none", "HS256", "HS384", "HS512"]);

function isRecord(v: unknown): v is Record<string, unknown> {
	return typeof v === "object" && v !== null && !Array.isArray(v);
}

function decodeSegment(segment: string): Record<string, unknown> | null {
	try {
		const parsed: unknown = JSON.parse(Buffer.from(segment, "base64url").toString("utf8"));
		return isRecord(parsed) ? parsed : null;
	} catch {
		return null;
	}
}

const iso = (seconds: unknown): string | null =>
	typeof seconds === "number" && Number.isFinite(seconds)
		? new Date(seconds * 1000).toISOString()
		: null;

export interface TokenReport {
	kind: "jwt" | "agent_token" | "opaque";
	length: number;
	[key: string]: unknown;
}

/**
 * Decode token metadata without verifying the signature. The raw token, its
 * signature and any non-standard claim values are never included.
 */
export function inspectToken(raw: string, now: Date = new Date()): TokenReport {
	const token = raw.trim().replace(/^Bearer\s+/i, "");
	const report: TokenReport = { kind: "opaque", length: token.length };

	if (token.startsWith(AGENT_TOKEN_PREFIX)) {
		return {
			...report,
			kind: "agent_token",
			note: "theAuth agent token (kv_ prefix). Opaque by design: status and permissions are only known to the server. Use list_agents or get_agent.",
		};
	}

	const parts = token.split(".");
	if (parts.length !== 3) {
		return { ...report, note: "Not a JWT (expected three dot-separated segments)." };
	}
	const header = decodeSegment(parts[0] ?? "");
	const claims = decodeSegment(parts[1] ?? "");
	if (!header || !claims) {
		return { ...report, note: "Three segments but header or payload is not valid base64url JSON." };
	}

	const warnings: string[] = [];
	const alg = typeof header.alg === "string" ? header.alg : null;
	if (alg && WEAK_ALGS.has(alg)) {
		warnings.push(
			alg === "none"
				? "alg is none: unsigned tokens must be rejected"
				: `alg ${alg} is a shared-secret algorithm; prefer ES256 or EdDSA for tokens verified by third parties`,
		);
	}
	const nowSec = Math.floor(now.getTime() / 1000);
	const exp = typeof claims.exp === "number" ? claims.exp : null;
	const nbf = typeof claims.nbf === "number" ? claims.nbf : null;
	let state: "valid_window" | "expired" | "not_yet_valid" | "no_expiry" = "valid_window";
	if (exp === null) {
		state = "no_expiry";
		warnings.push("no exp claim: token never expires");
	} else if (exp <= nowSec) {
		state = "expired";
	} else if (nbf !== null && nbf > nowSec) {
		state = "not_yet_valid";
	}
	if (claims.aud === undefined) warnings.push("no aud claim: audience binding is missing");
	if (typeof claims.iss !== "string") warnings.push("no iss claim");

	return {
		...report,
		kind: "jwt",
		signatureVerified: false,
		header: {
			alg,
			typ: typeof header.typ === "string" ? header.typ : null,
			kid: typeof header.kid === "string" ? header.kid : null,
		},
		claims: {
			iss: typeof claims.iss === "string" ? claims.iss : null,
			sub: typeof claims.sub === "string" ? claims.sub : null,
			aud: claims.aud ?? null,
			scope: typeof claims.scope === "string" ? claims.scope.split(/\s+/).filter(Boolean) : null,
			clientId: typeof claims.client_id === "string" ? claims.client_id : null,
			jti: typeof claims.jti === "string" ? claims.jti : null,
			issuedAt: iso(claims.iat),
			notBefore: iso(claims.nbf),
			expiresAt: iso(claims.exp),
			senderConstrained: isRecord(claims.cnf),
		},
		timeStatus: state,
		secondsRemaining: exp === null ? null : exp - nowSec,
		customClaimNames: Object.keys(claims).filter((k) => !KNOWN_CLAIMS.has(k)),
		warnings,
	};
}

export const inspectTokenTool = defineTool({
	name: "inspect_token",
	title: "Inspect token",
	description:
		"Decode a JWT access token or recognise a theAuth agent token and report its metadata: algorithm, issuer, subject, audience, scopes, expiry state and risk warnings. Local only: the signature is NOT verified, nothing is sent over the network, and the token itself is never echoed back.",
	inputSchema: {
		token: z
			.string()
			.min(1)
			.max(8192)
			.describe("The token to inspect (a leading 'Bearer ' is ignored)"),
	},
	async run(args) {
		const report = inspectToken(args.token);
		if (report.kind === "opaque" && typeof report.note !== "string") {
			return failure("UNRECOGNISED_TOKEN", "Token format not recognised");
		}
		return success(report);
	},
});
