import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

export const ATTEST_HELP = `
theauth device attest android --evidence <file> --nonce <nonce> --revocation google|off [options]
theauth device attest apple   --evidence <file> --nonce <nonce> --app-id <TeamID.BundleID> [options]
theauth device attest tpm     --evidence <file> --nonce <nonce> --root <file> | --allow-unverified-ak [options]

Checks evidence offline with the same verifier the enrollment hook uses. No config file is needed.
Exit code 0 when the evidence is accepted, 1 when it is refused.

android: the evidence file is a JSON array of base64 DER certificates, leaf first (KeyStore.getCertificateChain).
apple:   the evidence file is JSON { "attestation": "<base64>", "keyId": "<base64>" } (App Attest attestKey output).
tpm:     the evidence file is JSON { "akPublic", "quote", "signature", "pcrs", "akCertificates" }, see the IoT docs.

Common options:
  --evidence <file>         Evidence file
  --nonce <nonce>           The nonce the device bound into its evidence
  --root <file>             Trust anchor, PEM or base64 DER (repeatable). With --root only these are trusted
  --challenge utf8|base64url|hex   Encoding of the nonce (default utf8, tpm quotes often use hex)
  --key-thumbprint <t>      RFC 7638 thumbprint the attested key must have (android and apple, jwk credential binding)
  --now <iso time>          Verify as of this time
  --json                    Machine readable output

android options:
  --revocation google|off   Check serials against Google's status list, or skip (required, on purpose)
  --min-level tee|strongbox Lowest accepted security level (default tee)
  --boot verified|verified_or_self_signed|any   Boot policy (default verified)

apple options:
  --app-id <id>             Accepted App ID, TeamID.BundleID (required, repeatable)
  --environment production|development|any   AAGUID to accept (default production)
  --client-data-hash sha256|raw   How the app derived clientDataHash from its client data (default sha256)
  --bind client-data|attested-key|none   How the enrolled key is tied in (default: client-data when --key-thumbprint is given, else none)

tpm options:
  --allow-unverified-ak     Accept an attestation key without a certificate chain (development only)
  --pcr <bank>:<index>=<hex>   Expected PCR value, for example sha256:7=ab12... (repeatable)
`;

export interface AttestArgs {
	format: "android" | "apple" | "tpm";
	evidence?: string;
	nonce?: string;
	revocation?: "google" | "off";
	roots: string[];
	minLevel: "trusted_environment" | "strongbox";
	boot: "verified" | "verified_or_self_signed" | "any";
	keyThumbprint?: string;
	challenge: "utf8" | "base64url" | "hex";
	appIds: string[];
	environment: "production" | "development" | "any";
	clientDataHash: "sha256" | "raw";
	bind?: "client-data" | "attested-key" | "none";
	allowUnverifiedAk: boolean;
	pcrs: Record<string, Record<number, string>>;
	now?: Date;
	json: boolean;
	error: string | null;
}

const FORMATS = ["android", "apple", "tpm"] as const;

/** Parse the arguments after `device attest`. */
export function parseAttestArgs(args: string[]): AttestArgs {
	const [format, ...rest] = args;
	const out: AttestArgs = {
		format: FORMATS.find((f) => f === format) ?? "android",
		roots: [],
		minLevel: "trusted_environment",
		boot: "verified",
		challenge: "utf8",
		appIds: [],
		environment: "production",
		clientDataHash: "sha256",
		allowUnverifiedAk: false,
		pcrs: {},
		json: false,
		error: null,
	};
	if (!FORMATS.some((f) => f === format)) {
		out.error = "Supported attestation formats: android, apple, tpm";
		return out;
	}
	for (let i = 0; i < rest.length; i++) {
		const a = rest[i] ?? "";
		const v = rest[i + 1];
		switch (a) {
			case "--json":
				out.json = true;
				break;
			case "--allow-unverified-ak":
				out.allowUnverifiedAk = true;
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
			case "--app-id":
				if (v) out.appIds.push(v);
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
			case "--environment":
				if (v === "production" || v === "development" || v === "any") out.environment = v;
				else out.error ??= "--environment must be production, development or any";
				i++;
				break;
			case "--bind":
				if (v === "client-data" || v === "attested-key" || v === "none") out.bind = v;
				else out.error ??= "--bind must be client-data, attested-key or none";
				i++;
				break;
			case "--client-data-hash":
				if (v === "sha256" || v === "raw") out.clientDataHash = v;
				else out.error ??= "--client-data-hash must be sha256 or raw";
				i++;
				break;
			case "--pcr": {
				const m = /^(sha1|sha256|sha384|sha512):(\d{1,2})=([0-9a-fA-F]+)$/.exec(v ?? "");
				if (!m) out.error ??= "--pcr must look like sha256:7=<hex>";
				else {
					const bank = m[1] as string;
					out.pcrs[bank] = { ...out.pcrs[bank], [Number(m[2])]: m[3] as string };
				}
				i++;
				break;
			}
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
		else if (out.format === "android" && !out.revocation) {
			out.error = "Missing --revocation google|off";
		} else if (out.format === "apple" && out.appIds.length === 0) {
			out.error = "Missing --app-id <TeamID.BundleID>";
		} else if (out.format === "tpm" && out.roots.length === 0 && !out.allowUnverifiedAk) {
			out.error = "Pass --root <file> or --allow-unverified-ak";
		}
	}
	return out;
}

async function buildVerifier(args: AttestArgs, roots: string[]) {
	const core = await import("@glinr/theauth");
	const now = args.now ? { now: () => args.now as Date } : {};
	if (args.format === "apple") {
		return core.createAppleAppAttestVerifier({
			appIds: args.appIds,
			...(roots.length > 0 && { roots }),
			environment: args.environment,
			bind: args.bind ?? (args.keyThumbprint !== undefined ? "client-data" : "none"),
			clientDataHash: args.clientDataHash,
			challengeEncoding: args.challenge,
			...now,
		});
	}
	if (args.format === "tpm") {
		return core.createTpm2QuoteVerifier({
			...(roots.length > 0 && { roots }),
			allowUnverifiedAk: args.allowUnverifiedAk,
			challengeEncoding: args.challenge,
			expectedPcrs: args.pcrs,
			...now,
		});
	}
	return core.createAndroidKeyAttestationVerifier({
		revocation: args.revocation === "google" ? core.googleRevocationList() : "disabled",
		...(roots.length > 0 && { roots }),
		minSecurityLevel: args.minLevel === "strongbox" ? "strongbox" : "trusted_environment",
		bootPolicy: args.boot,
		bindKey: args.keyThumbprint !== undefined,
		challengeEncoding: args.challenge,
		...now,
	});
}

/** Run the check and return the text to print plus whether the evidence was accepted. */
export async function runAttest(args: AttestArgs): Promise<{ text: string; ok: boolean }> {
	const roots = await Promise.all(args.roots.map((f) => readFile(resolve(f), "utf8")));
	const evidence = await readFile(resolve(args.evidence ?? ""), "utf8");
	const verify = await buildVerifier(args, roots);
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
