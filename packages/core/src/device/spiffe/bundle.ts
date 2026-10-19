import type { JWK } from "jose";
import { z } from "zod";
import type { X509Cert } from "../attestation/x509.js";
import { certBytesFromText, parseCertificate } from "../attestation/x509.js";
import { basicConstraintsOf, keyUsageOf } from "./x509-info.js";

/**
 * A SPIFFE bundle (SPIFFE Trust Domain and Bundle, section 4) is a JWK Set with two extra members.
 * Entries with `use` x509-svid carry one CA certificate in `x5c` (base64 DER, RFC 7517 section 4.7),
 * entries with `use` jwt-svid carry a public key and a `kid`. Unknown `use` or `kty` values are ignored.
 */
const JwkEntry = z.object({
	kty: z.string(),
	use: z.string().optional(),
	kid: z.string().optional(),
	x5c: z.array(z.string()).optional(),
});
const BundleDocument = z.object({
	keys: z.array(JwkEntry.passthrough()),
	spiffe_sequence: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER).optional(),
	spiffe_refresh_hint: z.number().int().positive().max(31_536_000).optional(),
});

export interface SpiffeBundle {
	trustDomain: string;
	/** `spiffe_sequence`. A refresh that lowers it is refused (rollback). */
	sequence?: number;
	/** `spiffe_refresh_hint` in seconds. */
	refreshHintSeconds?: number;
	/** CA certificates that may anchor an X.509-SVID chain. */
	x509Authorities: X509Cert[];
	/** Public keys that may verify a JWT-SVID, by `kid`. */
	jwtAuthorities: Map<string, JWK>;
}

export type BundleParseResult =
	| { ok: true; bundle: SpiffeBundle; skipped: number }
	| { ok: false; reason: string };

const PRIVATE_MEMBERS = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

/** A bundle authority must be a CA that may sign certificates (X509-SVID section 4.1 and 4.3). */
function usableAuthority(cert: X509Cert): boolean {
	try {
		if (!basicConstraintsOf(cert).ca) return false;
		const ku = keyUsageOf(cert);
		return !ku.present || ku.keyCertSign;
	} catch {
		return false;
	}
}

export function parseSpiffeBundle(trustDomain: string, input: unknown): BundleParseResult {
	let raw: unknown = input;
	if (typeof input === "string") {
		try {
			raw = JSON.parse(input);
		} catch {
			return { ok: false, reason: "Bundle is not valid JSON" };
		}
	}
	const doc = BundleDocument.safeParse(raw);
	if (!doc.success) return { ok: false, reason: "Bundle is not a JWK Set" };
	const x509Authorities: X509Cert[] = [];
	const jwtAuthorities = new Map<string, JWK>();
	let skipped = 0;
	for (const key of doc.data.keys) {
		if (key.use === "x509-svid") {
			const first = key.x5c?.[0];
			if (!first) {
				skipped++;
				continue;
			}
			try {
				const cert = parseCertificate(certBytesFromText(first));
				if (usableAuthority(cert)) x509Authorities.push(cert);
				else skipped++;
			} catch {
				skipped++;
			}
		} else if (key.use === "jwt-svid") {
			// JWT-SVID section 6.1: published keys must carry a kid. A key with private members is refused.
			const rec = key as Record<string, unknown>;
			if (
				!key.kid ||
				PRIVATE_MEMBERS.some((m) => m in rec) ||
				(key.kty !== "RSA" && key.kty !== "EC")
			) {
				skipped++;
				continue;
			}
			if (jwtAuthorities.has(key.kid)) {
				return { ok: false, reason: "Bundle repeats a jwt-svid kid" };
			}
			jwtAuthorities.set(key.kid, rec as JWK);
		}
	}
	if (doc.data.keys.length > 0 && x509Authorities.length === 0 && jwtAuthorities.size === 0) {
		return { ok: false, reason: "Bundle has no usable authority" };
	}
	return {
		ok: true,
		skipped,
		bundle: {
			trustDomain,
			...(doc.data.spiffe_sequence !== undefined && { sequence: doc.data.spiffe_sequence }),
			...(doc.data.spiffe_refresh_hint !== undefined && {
				refreshHintSeconds: doc.data.spiffe_refresh_hint,
			}),
			x509Authorities,
			jwtAuthorities,
		},
	};
}

/** A bundle made only of PEM or base64 DER root certificates, for a trust domain with no JWT-SVIDs. */
export function bundleFromRoots(trustDomain: string, roots: string[]): BundleParseResult {
	const x509Authorities: X509Cert[] = [];
	for (const pem of roots) {
		for (const block of pem.match(
			/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g,
		) ?? [pem]) {
			try {
				const cert = parseCertificate(certBytesFromText(block));
				if (!usableAuthority(cert))
					return { ok: false, reason: "A root is not a CA that may sign certificates" };
				x509Authorities.push(cert);
			} catch {
				return { ok: false, reason: "A root certificate could not be parsed" };
			}
		}
	}
	if (x509Authorities.length === 0) return { ok: false, reason: "No root certificates given" };
	return {
		ok: true,
		skipped: 0,
		bundle: { trustDomain, x509Authorities, jwtAuthorities: new Map() },
	};
}
