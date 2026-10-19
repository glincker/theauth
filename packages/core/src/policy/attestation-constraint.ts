/**
 * Attestation constraint: a permission that only holds for a device whose verified hardware attestation (RFC 9334 Attester evidence, checked at enrollment) meets a bar. The facts are a small, format independent projection of the verified claims, so one rule works for Android Key Attestation, Apple App Attest and TPM 2.0 evidence. Pure functions, no I/O, mirrored by `iot/device` in the Go SDK and replayed from shared vectors.
 */

/** Where the attested key lives. `hardware` is a TEE, Secure Enclave or TPM, `strongbox` a dedicated secure element (Android StrongBox). */
export type AttestationFactLevel = "software" | "hardware" | "strongbox";

/** Boot integrity as far as the format can tell. Android reports it, the other formats do not. */
export type AttestationBootState =
	| "verified"
	| "self_signed"
	| "unverified"
	| "failed"
	| "unlocked";

export interface AttestationFacts {
	/** The verifier `format` claim, for example `android-key-attestation`. */
	format: string;
	securityLevel: AttestationFactLevel;
	/** Absent when the format carries no boot state (Apple App Attest, TPM quote). A rule that names `bootState` then fails closed. */
	bootState?: AttestationBootState;
	/** App identifiers the attestation covers: Android package names, or the Apple `teamId.bundleId`. */
	appIds?: string[];
}

/** The rule on `PermissionConstraints.attestation`. Every field that is set must hold. */
export interface AttestationConstraint {
	/** `hardware` accepts hardware and strongbox, `strongbox` accepts only strongbox. */
	minSecurityLevel?: "hardware" | "strongbox";
	/** The device boot state must be one of these. An empty list matches nothing. */
	bootState?: AttestationBootState[];
	/** One of the attested app ids must be in this list. An empty list matches nothing. */
	appIds?: string[];
}

const LEVEL_RANK: Record<AttestationFactLevel, number> = {
	software: 0,
	hardware: 1,
	strongbox: 2,
};

const SECURITY_LEVELS = new Set<string>(["software", "hardware", "strongbox"]);
const BOOT_STATES = new Set<string>([
	"verified",
	"self_signed",
	"unverified",
	"failed",
	"unlocked",
]);
/** What Android Key Attestation can report. `unlocked` is derived from `deviceLocked`, never read from the claim. */
const ANDROID_BOOT_STATES = new Set<string>(["verified", "self_signed", "unverified", "failed"]);

function str(v: unknown): string | undefined {
	return typeof v === "string" && v.length > 0 ? v : undefined;
}

function strList(v: unknown): string[] {
	return Array.isArray(v)
		? v.filter((x): x is string => typeof x === "string" && x.length > 0)
		: [];
}

/** Android reports TEE and StrongBox levels. The key level decides where the key lives, so the lower of the two wins. */
function androidLevel(a: unknown, k: unknown): AttestationFactLevel {
	const rank = (v: unknown): number =>
		v === "strongbox" ? 2 : v === "trusted_environment" ? 1 : 0;
	const low = Math.min(rank(a), k === undefined ? rank(a) : rank(k));
	return low === 2 ? "strongbox" : low === 1 ? "hardware" : "software";
}

/**
 * Project the claims a verifier returned at enrollment into the facts policy reads. Returns undefined for a claim set from an unknown format (a custom verifier), so a rule can never be satisfied by claims whose meaning is not known.
 * - `android-key-attestation`: level is the lower of attestation and key level (TEE is `hardware`). Boot state is the verified boot state, or `unlocked` when the bootloader is unlocked. App ids are the attested package names.
 * - `apple-app-attest`: the key is in the Secure Enclave, so `hardware`. No boot state. App id is the claimed `appId`.
 * - `tpm2-quote`: `hardware` only when the attestation key chained to a trusted root (`akVerified`), else `software`. No boot state, no app id.
 * - `tpm2-certify`: `hardware` only when the credential was activated and the endorsement key chained to a trusted root (`ekVerified`), else `software`.
 */
export function attestationFacts(
	claims: Record<string, unknown> | null | undefined,
): AttestationFacts | undefined {
	if (!claims) return undefined;
	switch (claims.format) {
		case "android-key-attestation": {
			const bs = str(claims.verifiedBootState);
			const bootState: AttestationBootState | undefined =
				claims.deviceLocked === false
					? "unlocked"
					: bs !== undefined && ANDROID_BOOT_STATES.has(bs)
						? (bs as AttestationBootState)
						: undefined;
			const appIds = strList(claims.packages);
			return {
				format: "android-key-attestation",
				securityLevel: androidLevel(claims.securityLevel, claims.keySecurityLevel),
				...(bootState !== undefined && { bootState }),
				...(appIds.length > 0 && { appIds }),
			};
		}
		case "apple-app-attest": {
			const appId = str(claims.appId);
			return {
				format: "apple-app-attest",
				securityLevel: "hardware",
				...(appId !== undefined && { appIds: [appId] }),
			};
		}
		case "tpm2-quote":
			return {
				format: "tpm2-quote",
				securityLevel: claims.akVerified === true ? "hardware" : "software",
			};
		case "tpm2-certify":
			// Activation ties the AK to the EK, and only an EK certificate that chains to a trusted root says the TPM is real.
			return {
				format: "tpm2-certify",
				securityLevel:
					claims.activated === true && claims.ekVerified === true ? "hardware" : "software",
			};
		default:
			return undefined;
	}
}

/** Narrow untrusted JSON (a bundle claim) into facts, or undefined when it is not well formed. */
export function parseAttestationFacts(value: unknown): AttestationFacts | undefined {
	if (value === null || typeof value !== "object" || Array.isArray(value)) return undefined;
	const v = value as Record<string, unknown>;
	const format = str(v.format);
	if (format === undefined || typeof v.securityLevel !== "string") return undefined;
	if (!SECURITY_LEVELS.has(v.securityLevel)) return undefined;
	const bs = str(v.bootState);
	const appIds = strList(v.appIds);
	return {
		format,
		securityLevel: v.securityLevel as AttestationFactLevel,
		...(bs !== undefined && BOOT_STATES.has(bs) && { bootState: bs as AttestationBootState }),
		...(appIds.length > 0 && { appIds }),
	};
}

export interface AttestationCheck {
	ok: boolean;
	reason?: string;
}

/** Check a rule against the facts. No facts fails closed: a rule is never satisfied by the absence of evidence. */
export function checkAttestationConstraint(
	rule: AttestationConstraint,
	facts: AttestationFacts | undefined,
): AttestationCheck {
	if (!facts) {
		return {
			ok: false,
			reason: "ATTESTATION_REQUIRED: This action needs a hardware attested device",
		};
	}
	// A rule can reach here from JSON that no schema checked (a bundle claim, a programmatic registration), so every field is checked for shape and a wrong shape denies.
	if (
		(rule.minSecurityLevel !== undefined &&
			!(
				typeof rule.minSecurityLevel === "string" &&
				Object.hasOwn(LEVEL_RANK, rule.minSecurityLevel)
			)) ||
		(rule.bootState !== undefined && !Array.isArray(rule.bootState)) ||
		(rule.appIds !== undefined && !Array.isArray(rule.appIds))
	) {
		return { ok: false, reason: "ATTESTATION_REQUIRED: Attestation rule is malformed" };
	}
	if (rule.minSecurityLevel !== undefined) {
		if (LEVEL_RANK[facts.securityLevel] < LEVEL_RANK[rule.minSecurityLevel]) {
			return {
				ok: false,
				reason: `ATTESTATION_REQUIRED: Device key security level "${facts.securityLevel}" is below the required "${rule.minSecurityLevel}"`,
			};
		}
	}
	if (rule.bootState !== undefined) {
		if (facts.bootState === undefined || !rule.bootState.includes(facts.bootState)) {
			return {
				ok: false,
				reason: `ATTESTATION_REQUIRED: Device boot state ${
					facts.bootState === undefined ? "is not attested" : `"${facts.bootState}" is not accepted`
				}`,
			};
		}
	}
	if (rule.appIds !== undefined) {
		const allowed = rule.appIds;
		if (!facts.appIds?.some((id) => allowed.includes(id))) {
			return { ok: false, reason: "ATTESTATION_REQUIRED: Attested app is not an allowed app" };
		}
	}
	return { ok: true };
}

/** Combine a parent and a child rule for delegation. The result is never looser than either. */
export function narrowAttestationConstraint(
	a: AttestationConstraint | undefined,
	b: AttestationConstraint | undefined,
): AttestationConstraint | undefined {
	if (!a) return b;
	if (!b) return a;
	const out: AttestationConstraint = {};
	if (a.minSecurityLevel || b.minSecurityLevel) {
		out.minSecurityLevel =
			a.minSecurityLevel === "strongbox" || b.minSecurityLevel === "strongbox"
				? "strongbox"
				: "hardware";
	}
	if (a.bootState || b.bootState) {
		out.bootState =
			a.bootState && b.bootState
				? b.bootState.filter((s) => a.bootState?.includes(s))
				: [...((a.bootState ?? b.bootState) as AttestationBootState[])];
	}
	if (a.appIds || b.appIds) {
		out.appIds =
			a.appIds && b.appIds
				? b.appIds.filter((s) => a.appIds?.includes(s))
				: [...((a.appIds ?? b.appIds) as string[])];
	}
	return out;
}
