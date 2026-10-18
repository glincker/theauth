import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

export const ATTEST_HELP = `
theauth device attest android --evidence <file> --nonce <nonce> --revocation google|off [options]

Checks an Android Key Attestation chain offline with the same verifier the enrollment hook uses.
The evidence file is a JSON array of base64 DER certificates, leaf first (KeyStore.getCertificateChain).
No config file is needed. Exit code 0 when the chain is accepted, 1 when it is refused.

Options:
  --evidence <file>         Evidence JSON file
  --nonce <nonce>           The nonce the device bound into the attestation challenge
  --revocation google|off   Check serials against Google's status list, or skip (required, on purpose)
  --root <file>             Extra trust anchor, PEM or base64 DER. With --root only these are trusted
  --min-level tee|strongbox Lowest accepted security level (default tee)
  --boot verified|verified_or_self_signed|any   Boot policy (default verified)
  --key-thumbprint <t>      RFC 7638 thumbprint the attested key must have (jwk credential binding)
  --challenge utf8|base64url|hex   Encoding of the nonce in the challenge (default utf8)
  --now <iso time>          Verify as of this time
  --json                    Machine readable output
`;

export interface AttestArgs {
	evidence?: string;
	nonce?: string;
	revocation?: "google" | "off";
	roots: string[];
	minLevel: "trusted_environment" | "strongbox";
	boot: "verified" | "verified_or_self_signed" | "any";
	keyThumbprint?: string;
	challenge: "utf8" | "base64url" | "hex";
	now?: Date;
	json: boolean;
	error: string | null;
}

/** Parse the arguments after `device attest`. */
export function parseAttestArgs(args: string[]): AttestArgs {
	const out: AttestArgs = {
		roots: [],
		minLevel: "trusted_environment",
		boot: "verified",
		challenge: "utf8",
		json: false,
		error: null,
	};
	const [format, ...rest] = args;
	if (format !== "android") {
		out.error = "Supported attestation format: android";
		return out;
	}
	for (let i = 0; i < rest.length; i++) {
		const a = rest[i] ?? "";
		const v = rest[i + 1];
		switch (a) {
			case "--json":
				out.json = true;
				break;
			case "--evidence":
				out.evidence = v;
				i++;
				break;
			case "--nonce":
				out.nonce = v;
				i++;
				break;
			case "--root":
				if (v) out.roots.push(v);
				i++;
				break;
			case "--key-thumbprint":
				out.keyThumbprint = v;
				i++;
				break;
			case "--revocation":
				if (v === "google" || v === "off") out.revocation = v;
				else out.error ??= "--revocation must be google or off";
				i++;
				break;
			case "--min-level":
				if (v === "tee") out.minLevel = "trusted_environment";
				else if (v === "strongbox") out.minLevel = "strongbox";
				else out.error ??= "--min-level must be tee or strongbox";
				i++;
				break;
			case "--boot":
				if (v === "verified" || v === "verified_or_self_signed" || v === "any") out.boot = v;
				else out.error ??= "--boot must be verified, verified_or_self_signed or any";
				i++;
				break;
			case "--challenge":
				if (v === "utf8" || v === "base64url" || v === "hex") out.challenge = v;
				else out.error ??= "--challenge must be utf8, base64url or hex";
				i++;
				break;
			case "--now": {
				const d = new Date(v ?? "");
				if (Number.isNaN(d.getTime())) out.error ??= "--now needs an ISO time";
				else out.now = d;
				i++;
				break;
			}
			default:
				out.error ??= `Unknown argument: ${a}`;
		}
	}
	if (!out.error) {
		if (!out.evidence) out.error = "Missing --evidence <file>";
		else if (!out.nonce) out.error = "Missing --nonce";
		else if (!out.revocation) out.error = "Missing --revocation google|off";
	}
	return out;
}

/** Run the check and return the text to print plus whether the evidence was accepted. */
export async function runAttest(args: AttestArgs): Promise<{ text: string; ok: boolean }> {
	const { createAndroidKeyAttestationVerifier, googleRevocationList } = await import(
		"@glinr/theauth"
	);
	const roots = await Promise.all(args.roots.map((f) => readFile(resolve(f), "utf8")));
	const evidence = await readFile(resolve(args.evidence ?? ""), "utf8");
	const verify = createAndroidKeyAttestationVerifier({
		revocation: args.revocation === "google" ? googleRevocationList() : "disabled",
		...(roots.length > 0 && { roots }),
		minSecurityLevel: args.minLevel === "strongbox" ? "strongbox" : "trusted_environment",
		bootPolicy: args.boot,
		bindKey: args.keyThumbprint !== undefined,
		challengeEncoding: args.challenge,
		...(args.now && { now: () => args.now as Date }),
	});
	const result = await verify({
		evidence,
		nonce: args.nonce ?? "",
		enrollmentId: "cli",
		...(args.keyThumbprint !== undefined && {
			credentialKind: "jwk" as const,
			credentialKeyThumbprint: args.keyThumbprint,
		}),
	});
	if (args.json) return { text: JSON.stringify(result, null, 2), ok: result.ok };
	if (!result.ok) return { text: `Refused: ${result.reason}`, ok: false };
	const c = result.claims ?? {};
	const lines = Object.entries(c).map(([k, val]) => `  ${k}: ${JSON.stringify(val)}`);
	return { text: `Accepted\n${lines.join("\n")}`, ok: true };
}
